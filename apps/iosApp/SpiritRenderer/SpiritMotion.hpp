#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <string>

namespace chur {
inline constexpr std::array<float, 12> apertureLevels = {
    0.f, .0025f, .005f, .01f, .025f, .075f, .15f, .3f, .5f, .7f, .85f, 1.f
};
inline constexpr std::array<const char*, 11> apertureNames = {
    "Aperture_00000", "Aperture_00025", "Aperture_00050", "Aperture_00100",
    "Aperture_00250", "Aperture_00750", "Aperture_01500", "Aperture_03000",
    "Aperture_05000", "Aperture_07000", "Aperture_08500"
};
inline float boundedInput(float value) {
    return std::isfinite(value) ? std::clamp(value, -1.f, 1.f) : 0.f;
}
inline float smoothStep(float x) {
    x = std::clamp(x, 0.f, 1.f);
    return x * x * (3.f - 2.f * x);
}
// Targets encode absolute aperture shapes; the full-open basis has no target.
inline std::array<float, 11> apertureWeights(float opening) {
    std::array<float, 11> weights{};
    opening = std::isfinite(opening) ? std::clamp(opening, 0.f, 1.f) : 1.f;
    if (opening >= 1.f) return weights;
    for (size_t i = 0; i + 1 < apertureLevels.size(); ++i) {
        if (opening <= apertureLevels[i + 1]) {
            const float t = (opening - apertureLevels[i]) / (apertureLevels[i + 1] - apertureLevels[i]);
            weights[i] = 1.f - t;
            if (i + 1 < weights.size()) weights[i + 1] = t;
            break;
        }
    }
    return weights;
}
struct ClipSample { std::string name; float seconds; };
inline ClipSample sampleClip(const std::string& requested, float elapsed, bool reduced) {
    if (reduced) return {requested == "sleep_enter" || requested == "sleep_loop" ? "sleep_loop" : "idle_soft", 0.f};
    const float t = std::max(0.f, elapsed);
    if (requested == "hold_enter") return t < .2f ? ClipSample{requested,t} : ClipSample{"hold_loop",std::fmod(t-.2f,1.2f)};
    if (requested == "tap_react" || requested == "release_settle") return t < .8f ? ClipSample{requested,t} : ClipSample{"idle_soft",std::fmod(t-.8f,4.f)};
    if (requested == "hold_loop") return {requested,std::fmod(t,1.2f)};
    if (requested == "sleep_enter") return t < 1.f ? ClipSample{requested,t} : ClipSample{"sleep_loop",std::fmod(t-1.f,3.f)};
    if (requested == "sleep_loop") return {requested,std::fmod(t,3.f)};
    if (requested == "wake") return t < .7f ? ClipSample{requested,t} : ClipSample{"idle_soft",std::fmod(t-.7f,4.f)};
    if (requested == "notice") return t < .6f ? ClipSample{requested,t} : ClipSample{"idle_soft",std::fmod(t-.6f,4.f)};
    return {"idle_soft",std::fmod(t,4.f)};
}
inline float blinkOpening(float seconds, float start, float closedFrom, float closedUntil, float end) {
    if (seconds <= start || seconds >= end) return 1.f;
    if (seconds < closedFrom) return 1.f - smoothStep((seconds - start) / (closedFrom - start));
    if (seconds <= closedUntil) return 0.f;
    return smoothStep((seconds - closedUntil) / (end - closedUntil));
}
// Fixed authored lengths, as in Kotlin SpiritEyes; exported clip lengths may round differently.
inline float clipDuration(const std::string& clip) {
    if (clip == "idle_soft") return 4.f;
    if (clip == "notice") return .6f;
    if (clip == "tap_react" || clip == "release_settle") return .8f;
    if (clip == "hold_enter") return .2f;
    if (clip == "hold_loop") return 1.2f;
    if (clip == "sleep_enter") return 1.f;
    if (clip == "sleep_loop") return 3.f;
    if (clip == "wake") return .7f;
    return 1.f;
}
inline float eyeOpening(const std::string& clip, float clipTime) {
    const float t = std::clamp(clipTime / clipDuration(clip), 0.f, 1.f);
    const float u = smoothStep(t);
    float opening = 1.f;
    if (clip == "idle_soft") opening = blinkOpening(clipTime, 2.60f, 2.66f, 2.78f, 2.90f);
    else if (clip == "tap_react") opening = blinkOpening(clipTime, .09f, .15f, .25f, .36f);
    else if (clip == "hold_enter") opening = 1.f - .16f * u;
    else if (clip == "hold_loop") opening = .84f;
    else if (clip == "release_settle") opening = .84f + .16f * u;
    else if (clip == "sleep_enter") opening = 1.f - u;
    else if (clip == "sleep_loop") opening = 0.f;
    else if (clip == "wake") opening = u;
    return std::clamp(opening, 0.f, 1.f);
}
} // namespace chur
