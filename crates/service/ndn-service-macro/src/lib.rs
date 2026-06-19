//! `#[ndn_service]` — turn a unary service trait into the service-layer §12
//! seam: per-operation `Frame` message types, a [`Dispatch`] that routes an
//! `OpId` to the typed handler, and a client generic over `C: Carrier`. The same
//! definition then runs over any carrier (Tier-0 `RpcCarrier`, the four-phase
//! `NdnsfCarrier`, v2) unchanged.
//!
//! ```ignore
//! #[ndn_service]
//! trait Echo {
//!     async fn echo(&self, msg: String) -> String;
//!     async fn ping(&self) -> u64;
//! }
//! // emits: EchoEchoRequest / EchoPingRequest (Frame), EchoDispatch<S: Echo>,
//! // EchoClient<C: Carrier> { echo(..), echo_select(.., Strategy) where C: SelectCarrier, ping(..), .. }
//! ```
//!
//! The trait's `async fn`s are rewritten to `-> impl Future + Send` (RPITIT), so
//! an implementor writes a plain `async fn` impl — no `#[async_trait]`. Argument
//! and return types must implement `ndn_service_core::Frame` (provided for
//! `String`, `Vec<u8>`, `Bytes`, the fixed-width integers, `bool`, and `()`).
//!
//! Requires `ndn-service-core` in the consuming crate; everything else
//! (`async_trait`, `bytes`, `ndn_packet`) is referenced through it.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, FnArg, Ident, ItemTrait, Pat, ReturnType, TraitItem, Type,
    parse_macro_input,
};

/// `#[derive(Frame)]` — derive `ndn_service_core::Frame` for a named-field struct,
/// composing each field's `Frame` (length-delimited, forward-compatible by
/// append). This is what makes a structured request **or response** type ergonomic
/// (e.g. a `Forecast { city, high_c, low_c, summary }` returned by a service op).
/// Every field type must itself implement `Frame`.
#[proc_macro_derive(Frame)]
pub fn derive_frame(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = &input.ident;
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return syn::Error::new_spanned(ident, "Frame derive requires named fields")
                    .to_compile_error()
                    .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(ident, "Frame derive requires a struct")
                .to_compile_error()
                .into();
        }
    };
    let names: Vec<&Ident> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    quote! {
        impl ::ndn_service_core::Frame for #ident {
            fn encode(&self) -> ::ndn_service_core::bytes::Bytes {
                ::ndn_service_core::framing::encode_fields(&[
                    #( ::ndn_service_core::Frame::encode(&self.#names) ),*
                ])
            }
            fn decode(__bytes: &[u8]) -> ::core::result::Result<Self, ::ndn_service_core::ServiceError> {
                let mut __pos = 0usize;
                ::core::result::Result::Ok(Self {
                    #( #names: <#types as ::ndn_service_core::Frame>::decode(
                        ::ndn_service_core::framing::read_field(__bytes, &mut __pos)?
                    )? ),*
                })
            }
        }
    }
    .into()
}

struct Method {
    name: Ident,
    arg_names: Vec<Ident>,
    arg_types: Vec<Type>,
    ret: Type,
}

/// PascalCase a snake_case method name for use in a generated type name.
fn pascal(ident: &Ident) -> String {
    ident
        .to_string()
        .split('_')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

#[proc_macro_attribute]
pub fn ndn_service(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut trait_def = parse_macro_input!(item as ItemTrait);
    let trait_ident = trait_def.ident.clone();

    // Parse each method and rewrite its async signature to RPITIT + Send.
    let mut methods = Vec::new();
    for it in &mut trait_def.items {
        let TraitItem::Fn(f) = it else { continue };
        let name = f.sig.ident.clone();
        let mut arg_names = Vec::new();
        let mut arg_types = Vec::new();
        for input in &f.sig.inputs {
            let FnArg::Typed(pt) = input else { continue }; // skip &self
            let Pat::Ident(pi) = &*pt.pat else {
                return syn::Error::new_spanned(&pt.pat, "ndn_service: each argument must be a plain identifier")
                    .to_compile_error()
                    .into();
            };
            arg_names.push(pi.ident.clone());
            arg_types.push((*pt.ty).clone());
        }
        let ret: Type = match &f.sig.output {
            ReturnType::Default => syn::parse_quote!(()),
            ReturnType::Type(_, t) => (**t).clone(),
        };
        if f.sig.asyncness.is_some() {
            f.sig.asyncness = None;
            f.sig.output =
                syn::parse_quote!(-> impl ::core::future::Future<Output = #ret> + ::core::marker::Send);
        }
        methods.push(Method {
            name,
            arg_names,
            arg_types,
            ret,
        });
    }

    // The trait gains Send + Sync + 'static so a provider can hold `Arc<S>`.
    trait_def.supertraits.push(syn::parse_quote!(::core::marker::Send));
    trait_def.supertraits.push(syn::parse_quote!(::core::marker::Sync));
    trait_def.supertraits.push(syn::parse_quote!('static));

    let dispatch_ident = format_ident!("{}Dispatch", trait_ident);
    let client_ident = format_ident!("{}Client", trait_ident);

    // Per-method generated pieces.
    let mut request_structs = Vec::new();
    let mut dispatch_arms = Vec::new();
    let mut client_methods = Vec::new();

    for m in &methods {
        let req_ident = format_ident!("{}{}Request", trait_ident, pascal(&m.name));
        let mname = &m.name;
        let op = m.name.to_string();
        let ret = &m.ret;
        let names = &m.arg_names;
        let types = &m.arg_types;

        request_structs.push(quote! {
            #[doc(hidden)]
            pub struct #req_ident { #( pub #names: #types ),* }
            impl ::ndn_service_core::Frame for #req_ident {
                fn encode(&self) -> ::ndn_service_core::bytes::Bytes {
                    ::ndn_service_core::framing::encode_fields(&[
                        #( ::ndn_service_core::Frame::encode(&self.#names) ),*
                    ])
                }
                fn decode(__bytes: &[u8])
                    -> ::core::result::Result<Self, ::ndn_service_core::ServiceError>
                {
                    let mut __pos = 0usize;
                    ::core::result::Result::Ok(Self {
                        #( #names: <#types as ::ndn_service_core::Frame>::decode(
                            ::ndn_service_core::framing::read_field(__bytes, &mut __pos)?
                        )? ),*
                    })
                }
            }
        });

        dispatch_arms.push(quote! {
            #op => {
                let __req = <#req_ident as ::ndn_service_core::Frame>::decode(&__inv.request)?;
                let __ret = self.0.#mname( #( __req.#names ),* ).await;
                ::core::result::Result::Ok(::ndn_service_core::Frame::encode(&__ret))
            }
        });

        let select_name = format_ident!("{}_select", m.name);
        client_methods.push(quote! {
            pub async fn #mname(&self, #( #names: #types ),* )
                -> ::core::result::Result<#ret, ::ndn_service_core::ServiceError>
            {
                let __req = #req_ident { #( #names ),* };
                let __resp = ::ndn_service_core::Carrier::invoke(
                    &self.carrier, &self.svc,
                    &::ndn_service_core::OpId::new(#op),
                    ::ndn_service_core::Frame::encode(&__req),
                ).await?;
                <#ret as ::ndn_service_core::Frame>::decode(&__resp.payload)
            }

            pub async fn #select_name(
                &self,
                #( #names: #types, )*
                __strategy: ::ndn_service_core::Strategy,
            ) -> ::core::result::Result<
                ::std::vec::Vec<(::ndn_service_core::ndn_packet::Name, #ret)>,
                ::ndn_service_core::ServiceError,
            >
            where
                C: ::ndn_service_core::SelectCarrier,
            {
                let __req = #req_ident { #( #names ),* };
                let __resps = ::ndn_service_core::SelectCarrier::invoke_select(
                    &self.carrier, &self.svc,
                    &::ndn_service_core::OpId::new(#op),
                    ::ndn_service_core::Frame::encode(&__req),
                    __strategy,
                ).await?;
                __resps.into_iter()
                    .map(|__r| <#ret as ::ndn_service_core::Frame>::decode(&__r.payload)
                        .map(|__v| (__r.producer, __v)))
                    .collect()
            }
        });
    }

    quote! {
        #trait_def

        #( #request_structs )*

        /// Server adapter: routes an [`Invocation`] to the typed service impl.
        pub struct #dispatch_ident<S: #trait_ident>(pub ::std::sync::Arc<S>);

        #[::ndn_service_core::async_trait::async_trait]
        impl<S: #trait_ident> ::ndn_service_core::Dispatch for #dispatch_ident<S> {
            async fn dispatch(&self, __inv: ::ndn_service_core::Invocation)
                -> ::core::result::Result<::ndn_service_core::bytes::Bytes, ::ndn_service_core::ServiceError>
            {
                match __inv.op.as_str() {
                    #( #dispatch_arms )*
                    _ => ::core::result::Result::Err(::ndn_service_core::ServiceError::NotFound),
                }
            }
        }

        /// Typed client, generic over any [`Carrier`]. Methods reaching many
        /// providers (`*_select`) require `C: SelectCarrier`.
        pub struct #client_ident<C: ::ndn_service_core::Carrier> {
            carrier: C,
            svc: ::ndn_service_core::ServiceId,
        }

        impl<C: ::ndn_service_core::Carrier> #client_ident<C> {
            /// A client for `svc` over `carrier`.
            pub fn new(carrier: C, svc: ::ndn_service_core::ServiceId) -> Self {
                Self { carrier, svc }
            }
            #( #client_methods )*
        }
    }
    .into()
}
