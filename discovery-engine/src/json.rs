use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use std::{cell::Cell, collections::BTreeSet, fmt};

struct Check<'a> {
    depth: usize,
    nodes: &'a Cell<usize>,
}
impl<'de> DeserializeSeed<'de> for Check<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        let nodes = self.nodes.get() + 1;
        self.nodes.set(nodes);
        if nodes > 250_000 || self.depth > 48 {
            return Err(D::Error::custom(
                "Discovery JSON exceeds its complexity limit",
            ));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Check<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON without duplicate keys")
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(Check {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 160 || keys.len() >= 16_384 || !keys.insert(key) {
                return Err(A::Error::custom("Invalid or duplicate discovery key"));
            }
            map.next_value_seed(Check {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
        }
        Ok(())
    }
}

pub fn check(input: &[u8]) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    Check {
        depth: 0,
        nodes: &Cell::new(0),
    }
    .deserialize(&mut deserializer)
    .map_err(|_| "Invalid discovery JSON")?;
    deserializer
        .end()
        .map_err(|_| "Invalid discovery JSON".into())
}
