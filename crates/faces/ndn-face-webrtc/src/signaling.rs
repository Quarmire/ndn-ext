//! Out-of-band signaling helpers. NDN-native signaling is deferred — it would
//! assume a discovery face that this transport is itself bootstrapping.

pub mod manual {
    //! Base64-encoded SDP + ICE blobs for manual paste rendezvous.
    //! Pre-handshake snapshot via [`encode_bundle`]; trickle additions via
    //! [`encode_candidate`] / [`decode_candidate`].

    use crate::{IceCandidate, SessionDescription, WebRtcError};
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    /// SDP description plus a snapshot of gathered ICE candidates. Does not
    /// support post-handshake trickle — use [`encode_candidate`] for that.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Bundle {
        pub description: SessionDescription,
        #[serde(default)]
        pub candidates: Vec<IceCandidate>,
    }

    pub fn encode_bundle(bundle: &Bundle) -> Result<String, WebRtcError> {
        let json = serde_json::to_vec(bundle)
            .map_err(|e| WebRtcError::Signaling(format!("encode bundle: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode_bundle(blob: &str) -> Result<Bundle, WebRtcError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(blob.trim())
            .map_err(|e| WebRtcError::InvalidBlob(format!("base64: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| WebRtcError::InvalidBlob(format!("json: {e}")))
    }

    pub fn encode_candidate(c: &IceCandidate) -> Result<String, WebRtcError> {
        let json = serde_json::to_vec(c)
            .map_err(|e| WebRtcError::Signaling(format!("encode candidate: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode_candidate(blob: &str) -> Result<IceCandidate, WebRtcError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(blob.trim())
            .map_err(|e| WebRtcError::InvalidBlob(format!("base64: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| WebRtcError::InvalidBlob(format!("json: {e}")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bundle_roundtrip() {
            let b = Bundle {
                description: SessionDescription {
                    kind: "offer".into(),
                    sdp: "v=0\r\n…".into(),
                },
                candidates: vec![IceCandidate {
                    candidate: "candidate:1 1 udp 2122260223 192.0.2.1 12345 typ host".into(),
                    sdp_mid: Some("0".into()),
                    sdp_m_line_index: Some(0),
                }],
            };
            let s = encode_bundle(&b).unwrap();
            let back = decode_bundle(&s).unwrap();
            assert_eq!(back.description.kind, "offer");
            assert_eq!(back.candidates.len(), 1);
            assert_eq!(back.candidates[0].sdp_mid.as_deref(), Some("0"));
        }

        #[test]
        fn candidate_roundtrip() {
            let c = IceCandidate {
                candidate: "candidate:9 1 udp 1686052607 198.51.100.7 54321 typ srflx \
                            raddr 192.0.2.1 rport 12345"
                    .into(),
                sdp_mid: Some("0".into()),
                sdp_m_line_index: Some(0),
            };
            let s = encode_candidate(&c).unwrap();
            let back = decode_candidate(&s).unwrap();
            assert_eq!(back.candidate, c.candidate);
        }

        #[test]
        fn rejects_non_base64() {
            assert!(decode_bundle("!!!not-base64!!!").is_err());
        }
    }
}
