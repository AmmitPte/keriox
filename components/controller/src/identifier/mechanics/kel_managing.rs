use keri_core::{
    actor::{event_generator, prelude::SelfAddressingIdentifier},
    event::{
        event_data::EventData,
        sections::{seal::Seal, threshold::SignatureThreshold, KeyConfig},
        KeyEvent,
    },
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice},
    },
    oobi::{LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use keri_core::prefix::CesrPrimitive;

use crate::identifier::Identifier;

use super::MechanicsError;

impl Identifier {
    /// Generate two rotation events:
    /// - first rotates from current signing keys to `rotation_keys`, with `new_signing_keys` as next keys,
    /// - second rotates from `rotation_keys` to `new_signing_keys`, with `new_next_keys` as next keys.
    /// The second event is generated against the post-first-rotation state.
    pub fn double_rotate(
        &self,
        rotation_keys: Vec<BasicPrefix>,
        new_signing_keys: Vec<BasicPrefix>,
        new_signing_threshold: u64,
        new_next_keys: Vec<BasicPrefix>,
        new_next_threshold: u64,
    ) -> Result<(String, String), MechanicsError> {
        let current_state = self.known_events.get_state(&self.id)?;
        let witness_threshold = match &current_state.witness_config.tally {
            SignatureThreshold::Simple(t) => *t,
            SignatureThreshold::Weighted(_) => {
                return Err(MechanicsError::OtherError(
                    "Weighted witness threshold is not supported in double_rotate".to_string(),
                ));
            }
        };

        let candidate_rotation_config = KeyConfig::new(
            rotation_keys.clone(),
            current_state.current.next_keys_data.clone(),
            None,
        );
        println!("verifying next");
        if !current_state
            .current
            .verify_next(&candidate_rotation_config)
            .map_err(|e| MechanicsError::OtherError(e.to_string()))?
        {
            return Err(MechanicsError::OtherError(
                "Rotation keys are not valid next keys for current identifier state".to_string(),
            ));
        }
        println!("check check 2");

        let SignatureThreshold::Simple(rotation_threshold) = current_state.current.next_keys_data.threshold  else {
            return Err(MechanicsError::OtherError(
                "Rotation threshold is not a simple threshold".to_string(),
            ));
        };
        println!("check check 3");
        let first_rotation = event_generator::rotate(
            current_state.clone(),
            rotation_keys.clone(),
            rotation_threshold,
            new_signing_keys.clone(),
            new_signing_threshold,
            vec![],
            vec![],
            witness_threshold,
        )
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let first_rotation_event = parse_event_type(first_rotation.as_bytes())
            .map_err(|_e| MechanicsError::EventFormatError)?;
        let first_rotation_event = if let EventType::KeyEvent(ke) = first_rotation_event {
            ke
        } else {
            return Err(MechanicsError::WrongEventTypeError);
        };

        let intermediate_state = current_state.apply(&first_rotation_event)?;
        let second_rotation = event_generator::rotate(
            intermediate_state,
            new_signing_keys,
            new_signing_threshold,
            new_next_keys,
            new_next_threshold,
            vec![],
            vec![],
            witness_threshold,
        )
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        Ok((first_rotation, second_rotation))
    }

    /// Generate and return rotation event for Identifier
    pub async fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        new_next_threshold: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        for wit_oobi in &witness_to_add {
            self.communication.resolve_loc_schema(wit_oobi).await?;
        }

        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(MechanicsError::WrongWitnessPrefixError)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let state = self.known_events.get_state(&self.id)?;
        let SignatureThreshold::Simple(rotation_threshold) = state.current.next_keys_data.threshold  else {
            return Err(MechanicsError::OtherError(
                "Rotation threshold is not a simple threshold".to_string(),
            ));
        };
        event_generator::rotate(
            state,
            current_keys,
            rotation_threshold,
            new_next_keys,
            new_next_threshold,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
        )
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    /// Generate and return interaction event for Identifier
    pub fn anchor(&self, payload: &[SelfAddressingIdentifier]) -> Result<String, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor(state, payload)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    pub fn anchor_with_seal(
        &self,
        seal_list: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor_with_seal(state, seal_list)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    pub async fn finalize_rotate(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            // Provide kel for new witnesses
            // TODO  should add to notify_witness instead of sending directly?
            match &ke.data.event_data {
                EventData::Rot(rot) | EventData::Drt(rot) => {
                    let own_kel = self.known_events.find_kel_with_receipts(&self.id).unwrap();
                    for witness in &rot.witness_config.graft {
                        let witness_id = IdentifierPrefix::Basic(witness.clone());
                        for msg in &own_kel {
                            self.communication
                                .send_message_to(
                                    witness_id.clone(),
                                    Scheme::Http,
                                    Message::Notice(msg.clone()),
                                )
                                .await?;
                        }
                    }
                }
                _ => (),
            };
            self.finalize_key_event(&ke, &sig)?;
            Ok(())
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    pub async fn finalize_multisig_rotate(
        &mut self,
        event: &[u8],
        sig: Vec<IndexedSignature>,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            // Provide kel for new witnesses
            // TODO  should add to notify_witness instead of sending directly?
            match &ke.data.event_data {
                EventData::Rot(rot) | EventData::Drt(rot) => {
                    let own_kel = self.known_events.find_kel_with_receipts(&self.id).unwrap();
                    for witness in &rot.witness_config.graft {
                        let witness_id = IdentifierPrefix::Basic(witness.clone());
                        for msg in &own_kel {
                            self.communication
                                .send_message_to(
                                    witness_id.clone(),
                                    Scheme::Http,
                                    Message::Notice(msg.clone()),
                                )
                                .await?;
                        }
                    }
                }
                _ => (),
            };
            self.finalize_key_event_multisig(&ke, sig)?;
            Ok(())
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    pub async fn finalize_anchor(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            match &ke.data.event_data {
                EventData::Ixn(_) => self.finalize_key_event(&ke, &sig),
                _ => Err(MechanicsError::WrongEventTypeError),
            }
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    /// Checks signatures and updates database.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function if event is a key event.
    pub(crate) fn finalize_key_event(
        &mut self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let own_index = self.get_index(&event.data).unwrap();
        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        self.known_events
            .save(&Message::Notice(Notice::Event(signed_message.clone())))?;

        let st = self.cached_state.clone().apply(event)?;
        self.cached_state = st;

        self.to_notify.push(signed_message);

        Ok(())
    }

    pub(crate) fn finalize_key_event_multisig(
        &mut self,
        event: &KeriEvent<KeyEvent>,
        sig: Vec<IndexedSignature>,
    ) -> Result<(), MechanicsError> {
        let signed_message = event.sign(sig, None, None);
        self.known_events
            .save(&Message::Notice(Notice::Event(signed_message.clone())))?;
    
        if let Ok(st) = self.cached_state.clone().apply(event) {
            self.cached_state = st;
        }

        self.to_notify.push(signed_message);

        Ok(())
    }

    pub fn index_in_current_keys(&self, key_config: &KeyConfig) -> Result<usize, MechanicsError> {
        // TODO what if group participant is a group and has more than one
        // public key?
        let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
        key_config
            .public_keys
            .iter()
            .position(|pk| pk.eq(&own_pk))
            .ok_or(MechanicsError::NotGroupParticipantError)
    }

    /// Helper function for getting the position of identifier's public key in
    /// group's current keys list.
    pub(crate) fn get_index(&self, key_event: &KeyEvent) -> Result<usize, MechanicsError> {
        match &key_event.event_data {
            EventData::Icp(icp) => self.index_in_current_keys(&icp.key_config),
            EventData::Rot(rot) => {
                let own_npk = &self.known_events.next_keys_hashes(&self.id)?[0];
                rot.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
                    .ok_or(MechanicsError::NotGroupParticipantError)
            }
            EventData::Dip(dip) => self.index_in_current_keys(&dip.inception_data.key_config),
            EventData::Drt(drt) => {
                let own_npk = &self.known_events.next_keys_hashes(&self.id)?[0];
                drt.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
                    .ok_or(MechanicsError::NotGroupParticipantError)
            }
            EventData::Ixn(_ixn) => {
                let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
                self.known_events
                    .current_public_keys(&key_event.get_prefix())?
                    .iter()
                    .position(|pk| pk.eq(&own_pk))
                    .ok_or(MechanicsError::NotGroupParticipantError)
            }
        }
    }
}
