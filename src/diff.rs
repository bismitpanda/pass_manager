use std::{fmt::Display, hash::Hash};

use hashbrown::{HashMap, HashSet};

pub struct Result<K> {
    pub added: HashSet<K>,
    pub modified: HashSet<K>,
    pub deleted: HashSet<K>,
}

#[derive(Clone)]
pub enum Item<T> {
    Added(T),
    Modified(T),
    Deleted(T),
}

impl<T: Display> Display for Item<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Added(k) => write!(f, "added '{k}'"),
            Self::Modified(k) => write!(f, "modified '{k}'"),
            Self::Deleted(k) => write!(f, "deleted '{k}'"),
        }
    }
}

impl<K> Result<K> {
    pub fn concat(self) -> Vec<Item<K>> {
        self.added
            .into_iter()
            .map(|el| Item::Added(el))
            .chain(self.modified.into_iter().map(|el| Item::Modified(el)))
            .chain(self.deleted.into_iter().map(|el| Item::Deleted(el)))
            .collect()
    }
}

pub fn diff<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> Result<K>
where
    K: Hash + Eq + Clone,
    V: PartialEq + Clone,
{
    let mut added = HashSet::new();
    let mut modified = HashSet::new();
    let mut deleted = HashSet::new();

    for key in lhs.keys() {
        if !rhs.contains_key(key) {
            deleted.insert(key.clone());
        }
    }

    for (key, new_value) in rhs {
        lhs.get(key).map_or_else(
            || {
                added.insert(key.clone());
            },
            |old_value| {
                if new_value != old_value {
                    modified.insert(key.clone());
                }
            },
        );
    }

    Result {
        added,
        modified,
        deleted,
    }
}
