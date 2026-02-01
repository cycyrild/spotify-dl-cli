use std::collections::VecDeque;

use anyhow::Context;

pub fn reconstruct_ogg_from_chunks<I>(chunks: I) -> impl Iterator<Item = Vec<u8>>
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let mut buf = VecDeque::<u8>::new();
    let mut probed = false;
    let mut last_page_no: Option<u32> = None;

    chunks
        .into_iter()
        .flat_map(move |data| {
            if data.is_empty() {
                return Vec::new();
            }

            let mut data = data;
            if !probed {
                probed = true;
                if !data.starts_with(b"OggS") {
                    return vec![];
                }
                let (maybe_trimmed, _) = skip_spotify_custom_page_if_present(&data);
                data = maybe_trimmed.to_vec();
            }

            buf.extend(data);
            let mut pages = Vec::new();
            loop {
                let Some(pos) = find_ogg_page(&buf) else {
                    trim_prefix(&mut buf);
                    break;
                };

                if buf.len() < pos + 27 {
                    trim_prefix(&mut buf);
                    break;
                }

                let header_type = buf[pos + 5];
                let pageno = u32::from_le_bytes([
                    buf[pos + 18],
                    buf[pos + 19],
                    buf[pos + 20],
                    buf[pos + 21],
                ]);
                let page_segments = buf[pos + 26] as usize;
                let header_len = 27 + page_segments;

                if buf.len() < pos + header_len {
                    trim_prefix(&mut buf);
                    break;
                }

                let body_len: usize = buf
                    .iter()
                    .skip(pos + 27)
                    .take(page_segments)
                    .map(|b| *b as usize)
                    .sum();
                let total_len = header_len + body_len;

                if buf.len() < pos + total_len {
                    trim_prefix(&mut buf);
                    break;
                }

                let page = buf
                    .iter()
                    .skip(pos)
                    .take(total_len)
                    .cloned()
                    .collect::<Vec<u8>>();

                let is_bos = header_type & 0x02 != 0;
                if let Some(last) = last_page_no {
                    if pageno != last + 1 {
                        return vec![];
                    }
                } else if !is_bos {
                    return vec![];
                }

                last_page_no = Some(pageno);
                for _ in 0..total_len {
                    buf.pop_front();
                }
                pages.push(page);
            }
            pages
        })
}

fn find_ogg_page(buf: &VecDeque<u8>) -> Option<usize> {
    buf.as_slices()
        .0
        .windows(4)
        .position(|w| w == b"OggS")
        .or_else(|| {
            let len_first = buf.as_slices().0.len();
            let combined: Vec<u8> = buf.iter().cloned().collect();
            combined
                .windows(4)
                .position(|w| w == b"OggS")
                .filter(|idx| *idx >= len_first)
        })
}

fn trim_prefix(buf: &mut VecDeque<u8>) {
    while buf.len() > 3 {
        let len = buf.len();
        if buf.make_contiguous()[len.saturating_sub(4)..].starts_with(b"OggS") {
            break;
        }
        buf.pop_front();
    }
}

fn skip_spotify_custom_page_if_present(chunk: &[u8]) -> (&[u8], bool) {
    if chunk.len() >= 4 && &chunk[..4] == b"OggS" {
        if let Some(idx) = find_next_ogg(chunk) {
            return (&chunk[idx..], true);
        }
    }
    (chunk, false)
}

fn find_next_ogg(data: &[u8]) -> Option<usize> {
    data.windows(4).skip(4).position(|w| w == b"OggS")
}
