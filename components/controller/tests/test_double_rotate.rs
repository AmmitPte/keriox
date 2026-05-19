//! Integration tests for [`keri_controller::identifier::Identifier::double_rotate`].
//! Kept in a separate crate test target so these can be run even if other
//! controller integration tests fail to compile against the current workspace.

use keri_core::{
    event::{event_data::EventData, sections::threshold::SignatureThreshold},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        signed_event_message::{Message, Notice},
    },
    prefix::{BasicPrefix, CesrPrimitive, IndexedSignature, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError};

#[async_std::test]
async fn test_double_rotate_apply_in_order() -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-double-rotate-db")
        .tempdir()
        .unwrap();

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;

    let mut km = CryptoBox::new()?;

    let first_pk = BasicPrefix::Ed25519(km.public_key());
    let first_next_npk = BasicPrefix::Ed25519(km.next_public_key());

    let inception_event = controller
        .incept(
            vec![first_pk.clone()],
            vec![first_next_npk.clone()],
            vec![],
            0,
        )
        .await?;

    let signature =
        SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);
    let mut identifier =
        controller.finalize_incept(inception_event.as_bytes(), &signature)?;

    assert_eq!(
        identifier.current_public_keys()?,
        vec![first_pk.clone()],
        "after inception, signing keys match initial pubkey"
    );

    // Promote inception `n` commitment to signer so rotation keys match `verify_next`.
    km.rotate()?;
    let rotation_keys = vec![BasicPrefix::Ed25519(km.public_key())];
    assert_eq!(
        rotation_keys,
        vec![first_next_npk.clone()],
        "rotation keys equal committed next keys from inception"
    );

    let new_signing_keys = vec![BasicPrefix::Ed25519(km.next_public_key())];

    let km_final_next = CryptoBox::new()?;
    let new_next_keys = vec![BasicPrefix::Ed25519(km_final_next.public_key())];

    let (first_rot, second_rot) = identifier.double_rotate(
        rotation_keys.clone(),
        new_signing_keys.clone(),
        1,
        new_next_keys.clone(),
        1,
    )?;

    let sig1 = SelfSigningPrefix::Ed25519Sha512(km.sign(first_rot.as_bytes())?);
    identifier
        .finalize_rotate(first_rot.as_bytes(), sig1)
        .await?;

    assert_eq!(
        identifier.current_public_keys()?,
        rotation_keys,
        "after first rotation of double_rotate, current keys are rotation (next) keys"
    );

    // Signer upgrades to committed next before the second establishment event.
    km.rotate()?;
    let sig2 = SelfSigningPrefix::Ed25519Sha512(km.sign(second_rot.as_bytes())?);
    identifier
        .finalize_rotate(second_rot.as_bytes(), sig2)
        .await?;

    assert_eq!(
        identifier.current_public_keys()?,
        new_signing_keys,
        "after second rotation, signing keys match intended new signing keys"
    );

    let next_hashes = identifier
        .known_events
        .next_keys_hashes(identifier.id())?;
    assert_eq!(next_hashes.len(), new_next_keys.len());
    assert!(next_hashes.iter().enumerate().all(|(i, h)| {
        h.verify_binding(new_next_keys[i].to_str().as_bytes())
    }));

    let state = identifier.find_state(identifier.id())?;
    // Inception is sn 0; each rotation increments by one (second rotation is sn 2).
    assert_eq!(state.sn, 2);

    Ok(())
}

#[async_std::test]
async fn test_double_rotate_from_one_of_one_to_two_of_two() -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-double-rotate-two-of-two-db")
        .tempdir()
        .unwrap();

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;

    let mut km = CryptoBox::new()?;
    let second_signing_km = CryptoBox::new()?;
    let final_next_km1 = CryptoBox::new()?;
    let final_next_km2 = CryptoBox::new()?;

    let first_pk = BasicPrefix::Ed25519(km.public_key());
    let first_next_npk = BasicPrefix::Ed25519(km.next_public_key());

    let inception_event = controller
        .incept(
            vec![first_pk.clone()],
            vec![first_next_npk.clone()],
            vec![],
            0,
        )
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);
    let mut identifier = controller.finalize_incept(inception_event.as_bytes(), &signature)?;

    let initial_state = identifier.find_state(identifier.id())?;
    assert_eq!(initial_state.current.public_keys, vec![first_pk]);
    assert_eq!(
        initial_state.current.threshold,
        SignatureThreshold::Simple(1)
    );
    assert_eq!(
        initial_state.current.next_keys_data.threshold,
        SignatureThreshold::Simple(1)
    );

    // Promote the committed 1-of-1 next key to the temporary rotation key.
    km.rotate()?;
    let rotation_keys = vec![BasicPrefix::Ed25519(km.public_key())];
    assert_eq!(rotation_keys, vec![first_next_npk]);

    let new_signing_keys = vec![
        BasicPrefix::Ed25519(km.next_public_key()),
        BasicPrefix::Ed25519(second_signing_km.public_key()),
    ];
    let new_next_keys = vec![
        BasicPrefix::Ed25519(final_next_km1.public_key()),
        BasicPrefix::Ed25519(final_next_km2.public_key()),
    ];

    let (first_rot, second_rot) = identifier.double_rotate(
        rotation_keys.clone(),
        new_signing_keys.clone(),
        2,
        new_next_keys.clone(),
        2,
    )?;

    let sig1 = SelfSigningPrefix::Ed25519Sha512(km.sign(first_rot.as_bytes())?);
    identifier
        .finalize_rotate(first_rot.as_bytes(), sig1)
        .await?;

    let after_first = identifier.find_state(identifier.id())?;
    assert_eq!(after_first.current.public_keys, rotation_keys);
    assert_eq!(after_first.current.threshold, SignatureThreshold::Simple(1));
    assert_eq!(
        after_first.current.next_keys_data.threshold,
        SignatureThreshold::Simple(2)
    );
    let signing_hashes = after_first.current.next_keys_data.next_keys_hashes();
    assert_eq!(signing_hashes.len(), new_signing_keys.len());
    assert!(signing_hashes
        .iter()
        .enumerate()
        .all(|(i, h)| h.verify_binding(new_signing_keys[i].to_str().as_bytes())));

    // The second rotation realizes the 2-of-2 signing keys, so both signers
    // must sign it before the event is accepted.
    km.rotate()?;
    let second_rot_event = match parse_event_type(second_rot.as_bytes())? {
        EventType::KeyEvent(ke) => ke,
        _ => panic!("double_rotate should generate a key event"),
    };

    match &second_rot_event.data.event_data {
        EventData::Rot(rot) => {
            assert_eq!(rot.key_config.public_keys, new_signing_keys);
            assert_eq!(rot.key_config.threshold, SignatureThreshold::Simple(2));
            assert_eq!(
                rot.key_config.next_keys_data.threshold,
                SignatureThreshold::Simple(2)
            );
        }
        _ => panic!("double_rotate should generate rotation events"),
    }

    let sigs = vec![
        IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(km.sign(second_rot.as_bytes())?),
            0,
        ),
        IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(second_signing_km.sign(second_rot.as_bytes())?),
            1,
        ),
    ];
    let signed_second_rot = second_rot_event.sign(sigs, None, None);
    identifier
        .known_events
        .process(&Message::Notice(Notice::Event(signed_second_rot)))?;

    let state = identifier.find_state(identifier.id())?;
    assert_eq!(state.sn, 2);
    assert_eq!(state.current.public_keys, new_signing_keys);
    assert_eq!(state.current.threshold, SignatureThreshold::Simple(2));
    assert_eq!(
        state.current.next_keys_data.threshold,
        SignatureThreshold::Simple(2)
    );

    let next_hashes = state.current.next_keys_data.next_keys_hashes();
    assert_eq!(next_hashes.len(), new_next_keys.len());
    assert!(next_hashes
        .iter()
        .enumerate()
        .all(|(i, h)| h.verify_binding(new_next_keys[i].to_str().as_bytes())));

    Ok(())
}

#[async_std::test]
async fn test_double_rotate_rejects_rotation_keys_not_in_next_commitment(
) -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-double-rotate-bad-next-db")
        .tempdir()
        .unwrap();

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;

    let km = CryptoBox::new()?;
    let other = CryptoBox::new()?;

    let first_pk = BasicPrefix::Ed25519(km.public_key());
    let first_next_npk = BasicPrefix::Ed25519(km.next_public_key());

    let inception_event = controller
        .incept(vec![first_pk.clone()], vec![first_next_npk], vec![], 0)
        .await?;

    let signature =
        SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);
    let identifier = controller.finalize_incept(inception_event.as_bytes(), &signature)?;

    let bogus_rotation_keys = vec![BasicPrefix::Ed25519(other.public_key())];

    assert!(
        identifier
            .double_rotate(bogus_rotation_keys, vec![], 1, vec![], 1)
            .is_err(),
        "rotation keys must bind to committed next keys"
    );

    Ok(())
}
