//! TEMPORARY skeptic repro — delete after verification.
use api_tracker_gateway::forward::BodyTap;
use api_tracker_gateway::usage::{Shape, UsageExtractor};

// Anthropic path: set_max puts input_tokens = u64::MAX, then
// Acc::add(input, cache_read_input_tokens) does MAX + 1.
#[test]
fn anthropic_cache_add_overflows() {
    let mut ex = UsageExtractor::new(Shape::Anthropic, true, false);
    ex.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":18446744073709551615,\"cache_read_input_tokens\":1,\"output_tokens\":1}}}\n\n");
    let out = ex.observation();
    eprintln!("survived feed: input_tokens = {:?}", out.input_tokens);
}

// OpenAI path: no `total_tokens`, so observation() computes i + o unchecked.
#[test]
fn openai_total_i_plus_o_overflows() {
    let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
    ex.feed(
        b"data: {\"usage\":{\"prompt_tokens\":18446744073709551615,\"completion_tokens\":2}}\n\n",
    );
    let out = ex.observation();
    eprintln!("survived observation: total = {:?}", out.total_tokens);
    // What writer.rs:627 would persist in release:
    if let Some(t) = out.total_tokens {
        eprintln!("as i64 => {}", t as i64);
    }
    if let Some(i) = out.input_tokens {
        eprintln!("input as i64 => {}", i as i64);
    }
}
