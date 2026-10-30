#pragma once
#include <gltfio/math.h>
#include <math/mat4.h>
#include <math/quat.h>

namespace chur {
// TRS crossfade of one local transform. Kotlin blendSpiritPose is the Android twin; the parity check compares them.
inline filament::math::mat4f blendPose(const filament::math::mat4f& from, const filament::math::mat4f& to, float alpha) {
    using namespace filament::math;
    float3 fromTranslation, fromScale, toTranslation, toScale;
    quatf fromRotation, toRotation;
    filament::gltfio::decomposeMatrix(from, &fromTranslation, &fromRotation, &fromScale);
    filament::gltfio::decomposeMatrix(to, &toTranslation, &toRotation, &toScale);
    return filament::gltfio::composeMatrix(mix(fromTranslation, toTranslation, alpha),
        normalize(fromRotation * (1.f - alpha) + toRotation * (dot(fromRotation, toRotation) < 0.f ? -alpha : alpha)),
        mix(fromScale, toScale, alpha));
}
} // namespace chur
