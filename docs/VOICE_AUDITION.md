# Gate 0 — Spanish voice audition

**Status: NOT YET COMPLETED.** Fill this in before enabling Spanish Coach for the kids.

The coach's voice *is* the pronunciation curriculum. There is no textbook and no teacher —
the children learn to pronounce Spanish by imitating whatever this voice does, fifteen
minutes a day. A voice with an anglophone accent doesn't just sound off; it actively
teaches incorrect Spanish. That is why this is a gate and not a nice-to-have.

## What to audition

Spanish Coach ships with Engine P (pipeline), which uses **`gpt-4o-mini-tts`**. The voice is
set by `SPANISH_TTS_VOICE` in `wrangler.toml` (default `coral`).

Audition at **<https://openai.fm>** — free, no setup, all voices, and an instructions box.

> If Engine R (realtime speech-to-speech) is ever added, its voices are a **different speech
> engine** and must be auditioned separately at the Realtime playground. A good result here
> does not transfer.

## Test script

Paste this in and listen:

```
Pero el perro no nada nada.
¿Tú tienes tiempo para hablar de tu día?
Ayer fui al parque con mi familia. Vimos muchos pájaros y un perro
muy rápido. ¿Qué hiciste tú ayer por la tarde?
```

Use these instructions (they match what the Worker actually sends):

```
Speak as a warm, patient adult talking with a young child learning Spanish.
Natural Latin American Spanish, clear and unhurried, friendly and encouraging.
```

## The six tells

Judge each one. A fluent Spanish speaker is ideal; otherwise listen for these specifically.

| # | Feature | Pass | Fail | Result |
|---|---------|------|------|--------|
| 1 | **Pure vowels** | "no" is one clean vowel | "nou" — an English diphthong | ☐ |
| 2 | **Tap vs. trill** | *pero* (tap) ≠ *perro* (trill) | English "r" for both | ☐ |
| 3 | **Soft /d/** | *nada* ≈ "NAH-tha" | hard English "d" | ☐ |
| 4 | **Unaspirated /t/ /p/** | *tienes* with no puff of air | aspirated like English "tea" | ☐ |
| 5 | **Syllable timing** | even, syllable-timed | bouncy English stress-timing | ☐ |
| 6 | **No schwa** | unstressed vowels stay full | any "uh" sound | ☐ |

**Tell #1 decides it in the first three words.** If "no" comes out as "nou", the voice is
wearing an American accent — try another voice before accepting it.

Voices worth trying: **coral**, **nova**, **sage**, **shimmer**, **alloy**, **ash**.

## Decision

| Field | Value |
|-------|-------|
| Date | |
| Model | `gpt-4o-mini-tts` |
| Voices tried | |
| Voice chosen | |
| Tells passed | ___ / 6 |
| Judged by | |
| Notes | |

Then set the chosen voice:

```toml
# wrangler.toml
SPANISH_TTS_VOICE = "coral"
```

## If no voice passes

Fall back to **Google Chirp 3 HD `es-US`**, which is locale-pinned (built for Spanish rather
than English-optimized) and can be auditioned in Speech Studio:
<https://console.cloud.google.com/speech/text-to-speech>

Voice IDs look like `es-US-Chirp3-HD-Kore`. Swapping engines is a change to one function —
`spanishSynthesize()` in `worker.js` — because the pipeline architecture keeps the audio
layer isolated. Note Chirp 3 HD has **no `es-MX`**; `es-US` is US Latino Spanish and is the
closest fit.
