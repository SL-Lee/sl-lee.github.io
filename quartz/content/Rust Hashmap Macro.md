---
created: 2020-10-06T20:04:00
---
# Rust Hashmap Macro

A hashmap macro to construct a hashmap quickly, similar to the `vec!` macro.

Definition:

```rust
use std::collections::HashMap;

#[macro_export]
macro_rules! hashmap {
    ( $key_type:ty; $value_type:ty ) => {
        HashMap::<$key_type, $value_type>::new()
    };
    ( $( $key:expr => $value:expr ),+ $(,)? ) => {
        {
            let mut hashmap = HashMap::new();
            $( hashmap.insert($key, $value); )*
            hashmap
        }
    };
}
```

Example usage:

```rust
// Create a new, empty hashmap where its keys are `String`s and
// its values are `u32`s
let mut hashmap1 = hashmap!{String; u32};

// Create a new hashmap and insert two pairs of keys and values to it
let mut hashmap2 = hashmap!{
    "key1".to_string() => "value1".to_string(),
    "key2".to_string() => "value2".to_string(),
};
```
