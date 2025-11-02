// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Validador de imagens (PNG/JPEG/WebP/GIF etc.).

use super::ValidatorOutcome;
use crate::policy::ResolvedPolicy;
use image::codecs::gif::GifDecoder;
use image::{AnimationDecoder, ImageReader};
use serde_json::json;
use std::io::Cursor;

pub fn validate_image(
    mime: &str,
    data: &[u8],
    policy: Option<&ResolvedPolicy>,
) -> ValidatorOutcome {
    let name = "image";
    let reader = match ImageReader::new(Cursor::new(data)).with_guessed_format() {
        Ok(reader) => reader,
        Err(err) => {
            return ValidatorOutcome::error(
                name,
                format!("falha ao detectar formato de imagem: {err}"),
            )
        }
    };

    let format = reader.format();
    let dimensions = match reader.into_dimensions() {
        Ok(dim) => dim,
        Err(err) => {
            return ValidatorOutcome::deny(
                name,
                format!("não foi possível ler dimensões da imagem: {err}"),
            )
        }
    };

    let (width, height) = dimensions;
    let mut details = json!({
        "mime": mime,
        "width": width,
        "height": height,
    });
    if let Some(fmt) = format {
        let extensions = fmt.extensions_str();
        if !extensions.is_empty() {
            details["format"] = json!(extensions.join(","));
        }
    }

    let image_policy = policy.map(|p| p.image.clone()).unwrap_or_default();

    if let Some([max_w, max_h]) = image_policy.max_dimensions {
        if width > max_w || height > max_h {
            return ValidatorOutcome::deny(
                name,
                format!(
                    "dimensões excedem o limite configurado: {width}x{height} > {max_w}x{max_h}"
                ),
            );
        }
    }

    let mut frame_count = 1u32;
    if mime.eq_ignore_ascii_case("image/gif") {
        if let Ok(decoder) = GifDecoder::new(Cursor::new(data)) {
            let frames = decoder.into_frames();
            frame_count = frames.into_iter().count() as u32;
        }
    }
    details["frames"] = json!(frame_count);

    if let Some(max_frames) = image_policy.max_frames {
        if frame_count > max_frames {
            return ValidatorOutcome::deny(
                name,
                format!("frames excedem o limite permitido: {frame_count} > {max_frames}"),
            );
        }
    }

    if let Some(mode) = image_policy.strip_metadata.as_deref() {
        if mode.eq_ignore_ascii_case("deny") {
            // Ainda não implementamos strip automático.
            return ValidatorOutcome::warn(
                name,
                "strip de metadados não implementado — arquivo retornado sem alterações",
            );
        }
    }

    let mut outcome = ValidatorOutcome::pass(name);
    outcome.details = details;
    outcome
}
