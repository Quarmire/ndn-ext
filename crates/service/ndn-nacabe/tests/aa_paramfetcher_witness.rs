#![cfg(feature = "service")]
//! End-to-end witness for the NAC attribute-authority serve/fetch shell.
//!
//! Over an in-process engine: the authority serves `PUBPARAMS` and answers a
//! signed `DKEY` request by sealing the issued key to the requester's ephemeral
//! X25519 key; the `ParamFetcher` obtains it and decrypts NAC content. Exercises
//! NSF-A1 (request validated, response verified) and NSF-A2 (key issued to the
//! validated signer's identity) end-to-end. Run with `--features service`.

use std::sync::Arc;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_foundation_types::Hash;
use ndn_nacabe::{CpAuthority, ParamFetcher, open_cp, open_cp_dkey, seal_cp, serve_cp};
use ndn_packet::Name;
use ndn_sealed_box::Recipient;
use ndn_security::KeyChain;
use ndn_security::abe::{PolicyExpr, bsw_setup};
use ndn_transport::FaceId;

#[tokio::test]
async fn aa_serves_params_and_issues_sealed_dkey_over_ndn() {
    let aa_kc = KeyChain::ephemeral("/muas/aa").unwrap();
    let alice_kc = KeyChain::ephemeral("/muas/alice").unwrap();
    let aa_prefix: Name = "/muas/aa".parse().unwrap();

    // CP-ABE authority; alice is granted role:analyst.
    let (mp, ms) = bsw_setup().unwrap();
    let mut authority = CpAuthority::new(mp.clone(), ms);
    authority.grant("/muas/alice".parse().unwrap(), vec!["role:analyst".into()]);
    let authority = Arc::new(authority);

    // In-proc engine: consumer (alice) face + producer (AA) face; /muas/aa -> AA.
    let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
    let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(&aa_prefix, FaceId(2), 0);

    let producer = Producer::from_handle(p_handle, aa_prefix.clone());
    let consumer = Consumer::from_handle(c_handle);

    // AA serve loop: validates DKEY requests against alice's anchor, signs responses.
    let serve = tokio::spawn(serve_cp(
        producer,
        aa_prefix.clone(),
        authority.clone(),
        aa_kc.signer().unwrap(),
        Arc::new(alice_kc.validator()),
    ));

    // alice's ParamFetcher verifies AA responses against the AA's anchor.
    let mut fetcher = ParamFetcher::new(consumer, aa_prefix.clone(), Arc::new(aa_kc.validator()));

    // 1. PUBPARAMS over NDN match the authority's.
    let params = fetcher.fetch_public_params().await.unwrap();
    assert_eq!(params, authority.public_params());

    // 2. alice obtains her sealed DKEY (signed request -> validated -> sealed to her).
    let recipient = Recipient::generate().unwrap();
    let recipient_pub = recipient.public;
    let signer = alice_kc.signer().unwrap();
    let sealed = fetcher
        .obtain_decryption_key(&*signer, &recipient_pub)
        .await
        .unwrap();
    let keys = open_cp_dkey(recipient, &sealed).unwrap();

    // 3. the obtained key decrypts NAC content under a policy alice satisfies.
    let kgc = (aa_prefix.clone(), Hash::of(&mp.public_key_bytes), mp);
    let policy = PolicyExpr::parse("role:analyst OR role:commander").unwrap();
    let (ck_data, content) =
        seal_cp("/p/CK/1".parse().unwrap(), &policy, &kgc, b"intel", b"/intel/v1").unwrap();
    assert_eq!(
        open_cp(&ck_data, &keys, &content, b"/intel/v1").unwrap(),
        b"intel"
    );

    drop(fetcher);
    drop(engine);
    shutdown.shutdown().await;
    serve.abort();
}
