#include "SpiritScene.hpp"
#include "SpiritMotion.hpp"
#include "SpiritTail.hpp"
#include <filament/Camera.h>
#include <filament/Engine.h>
#include <filament/IndirectLight.h>
#include <filament/LightManager.h>
#include <filament/RenderableManager.h>
#include <filament/Renderer.h>
#include <filament/Scene.h>
#include <filament/SwapChain.h>
#include <filament/TransformManager.h>
#include <filament/View.h>
#include <filament/Viewport.h>
#include <gltfio/Animator.h>
#include <gltfio/AssetLoader.h>
#include <gltfio/FilamentAsset.h>
#include <gltfio/FilamentInstance.h>
#include <gltfio/MaterialProvider.h>
#include <gltfio/ResourceLoader.h>
#include <gltfio/TextureProvider.h>
#include <gltfio/materials/uberarchive.h>
#include <gltfio/math.h>
#include <utils/EntityManager.h>
#include <utils/NameComponentManager.h>
#include <math/mat4.h>
#include <math/quat.h>
#include <array>
#include <limits>
#include <map>
#include <utility>
#include <vector>

namespace chur {
using namespace filament;
using namespace filament::gltfio;
using namespace filament::math;
using utils::Entity;

struct SpiritScene::Impl {
    Engine* engine = nullptr;
    Renderer* renderer = nullptr;
    Scene* scene = nullptr;
    View* view = nullptr;
    SwapChain* swapChain = nullptr;
    Camera* camera = nullptr;
    Entity cameraEntity{}, lightEntity{};
    IndirectLight* indirect = nullptr;
    std::unique_ptr<utils::NameComponentManager> names;
    MaterialProvider* materials = nullptr;
    AssetLoader* loader = nullptr;
    FilamentAsset* asset = nullptr;
    TextureProvider* textureProvider = nullptr;
    std::unique_ptr<ResourceLoader> resources;
    Animator* animator = nullptr;
    std::map<std::string, size_t> clips;
    std::vector<std::pair<Entity, mat4f>> rest;
    std::array<Entity, 2> eyes{};
    std::vector<mat4f> fadeFrom, displayedPose;
    std::array<Entity, 8> tails{};
    std::array<float, 8> tailSignals{};
    float motionInputAge = 1.f;
    uint32_t width = 0, height = 0;
    std::string failure, current = "idle_soft", requested = "idle_soft";
    int32_t serial = std::numeric_limits<int32_t>::min();
    int32_t motionSerial = std::numeric_limits<int32_t>::min();
    bool reduced = false;
    float time = 0.f, fade = 1.f, dragX = 0.f, dragY = 0.f;
    float lastOpening = 1.f, fromOpening = 1.f;
    float leanX = 0.f, leanY = 0.f;

    bool ready() const { return failure.empty() && animator && swapChain; }
    void transition(std::string clip) {
        if (clips.find(clip) == clips.end()) clip = "idle_soft";
        // Snapshot the displayed pose, including an interrupted crossfade.
        // Re-sampling only the previous requested clip would cause a jump.
        fadeFrom = displayedPose;
        if (fadeFrom.size() != rest.size()) {
            fadeFrom.clear();
            for (const auto& entry : rest) fadeFrom.push_back(entry.second);
        }
        fromOpening = lastOpening;
        current = std::move(clip);
        time = 0.f;
        fade = 0.f;
    }
    ~Impl() {
        if (!engine) return;
        // ResourceLoader retains texture callbacks; destroy it before the provider.
        resources.reset();
        delete textureProvider;
        if (asset) {
            if (scene) scene->removeEntities(asset->getEntities(), asset->getEntityCount());
            loader->destroyAsset(asset);
        }
        if (loader) AssetLoader::destroy(&loader);
        if (materials) { materials->destroyMaterials(); delete materials; }
        names.reset();
        if (view) engine->destroy(view);
        if (scene) engine->destroy(scene);
        if (indirect) engine->destroy(indirect);
        if (lightEntity) { engine->destroy(lightEntity); utils::EntityManager::get().destroy(lightEntity); }
        if (cameraEntity) {
            engine->destroyCameraComponent(cameraEntity);
            utils::EntityManager::get().destroy(cameraEntity);
        }
        if (renderer) engine->destroy(renderer);
        if (swapChain) engine->destroy(swapChain);
        engine->flushAndWait();
        Engine::destroy(&engine);
    }
};

SpiritScene::SpiritScene(void* metalLayer, const uint8_t* glb, size_t bytes) : impl_(new Impl) {
    auto& s = *impl_;
    if (!metalLayer || !glb || bytes == 0 || bytes > UINT32_MAX) {
        s.failure = "The bundled spirit model is missing or too large."; return;
    }
    s.engine = Engine::create(Engine::Backend::METAL);
    if (!s.engine) { s.failure = "Metal rendering is unavailable."; return; }
    s.renderer = s.engine->createRenderer();
    s.scene = s.engine->createScene();
    s.view = s.engine->createView();
    s.swapChain = s.engine->createSwapChain(metalLayer, SwapChain::CONFIG_TRANSPARENT);
    if (!s.swapChain) { s.failure = "The transparent Metal surface could not be created."; return; }
    s.cameraEntity = utils::EntityManager::get().create();
    s.camera = s.engine->createCamera(s.cameraEntity);
    s.camera->lookAt({0, 0, 4}, {0, 0, 0}, {0, 1, 0});
    s.camera->setExposure(16.f, 1.f / 125.f, 100.f);
    s.view->setScene(s.scene);
    s.view->setCamera(s.camera);
    s.view->setBlendMode(View::BlendMode::TRANSLUCENT);
    s.view->setShadowingEnabled(false);
    s.view->setPostProcessingEnabled(false);
    Renderer::ClearOptions clear;
    clear.clear = true; clear.discard = true; clear.clearColor = {0, 0, 0, 0};
    s.renderer->setClearOptions(clear);

    s.lightEntity = utils::EntityManager::get().create();
    LightManager::Builder(LightManager::Type::SUN)
        .color({1.f, .96f, .9f}).intensity(100000.f).direction({-.4f, -.6f, -1.f})
        .castShadows(false).build(*s.engine, s.lightEntity);
    s.scene->addEntity(s.lightEntity);
    s.names = std::make_unique<utils::NameComponentManager>(utils::EntityManager::get());
    s.materials = createUbershaderProvider(s.engine, UBERARCHIVE_DEFAULT_DATA, UBERARCHIVE_DEFAULT_SIZE);
    AssetConfiguration config{};
    config.engine = s.engine; config.materials = s.materials; config.names = s.names.get();
    s.loader = AssetLoader::create(config);
    s.asset = s.loader->createAsset(glb, uint32_t(bytes));
    if (!s.asset) { s.failure = "The spirit GLB could not be decoded."; return; }
    if (s.asset->getResourceUriCount() != 0) {
        s.failure = "The spirit GLB must be self-contained."; return;
    }
    s.textureProvider = createStbProvider(s.engine);
    s.resources = std::make_unique<ResourceLoader>(ResourceConfiguration{s.engine, nullptr, true});
    s.resources->addTextureProvider("image/png", s.textureProvider);
    s.resources->addTextureProvider("image/jpeg", s.textureProvider);
    if (!s.resources->loadResources(s.asset)) { s.failure = "Spirit resources could not be uploaded."; return; }
    s.animator = s.asset->getInstance()->getAnimator();
    for (size_t i = 0; i < s.animator->getAnimationCount(); ++i) {
        s.clips.emplace(s.animator->getAnimationName(i), i);
    }
    const char* required[] = {"idle_soft", "notice", "tap_react", "hold_enter", "hold_loop",
        "release_settle", "sleep_enter", "sleep_loop", "wake"};
    for (const auto* name : required) {
        if (!s.clips.count(name)) { s.failure = std::string("Missing spirit animation: ") + name; return; }
    }
    auto& transforms = s.engine->getTransformManager();
    auto& renderables = s.engine->getRenderableManager();
    for (size_t i = 0; i < s.asset->getEntityCount(); ++i) {
        const Entity entity = s.asset->getEntities()[i];
        const auto transform = transforms.getInstance(entity);
        if (transform && entity != s.asset->getRoot()) s.rest.emplace_back(entity, transforms.getTransform(transform));
        const auto renderable = renderables.getInstance(entity);
        // Imported bind-pose bounds can miss the animated tail and eye morphs.
        if (renderable) renderables.setCulling(renderable, false);
    }
    s.eyes = {s.asset->getFirstEntityByName("Spirit_Eye_L"), s.asset->getFirstEntityByName("Spirit_Eye_R")};
    for (Entity eye : s.eyes) {
        if (!eye || s.asset->getMorphTargetCountAt(eye) != apertureNames.size()) {
            s.failure = "The spirit eye aperture contract does not match."; return;
        }
        for (size_t i = 0; i < apertureNames.size(); ++i) {
            const char* name = s.asset->getMorphTargetNameAt(eye, i);
            if (!name || std::string(name) != apertureNames[i]) {
                s.failure = "The spirit eye morph order does not match."; return;
            }
        }
    }
    for (size_t i = 0; i < s.tails.size(); ++i) {
        s.tails[i] = s.asset->getFirstEntityByName(tailNames[i]);
        if (!s.tails[i]) { s.failure = "The spirit tail contract does not match."; return; }
    }
    s.scene->addEntities(s.asset->getEntities(), s.asset->getEntityCount());
    // Animator and morph-name metadata were resolved before releasing GLB source data.
    s.asset->releaseSourceData();
}

SpiritScene::~SpiritScene() = default;
bool SpiritScene::ready() const { return impl_->ready(); }
const std::string& SpiritScene::error() const { return impl_->failure; }
void SpiritScene::resize(uint32_t width, uint32_t height) {
    auto& s = *impl_;
    s.width = width; s.height = height;
    if (!s.ready() || width == 0 || height == 0) return;
    const double aspect = double(width) / height;
    const double vertical = 1.125 * std::max(1., 1. / aspect); // Preserve square safe bounds in narrow surfaces.
    s.camera->setProjection(Camera::Projection::ORTHO, -vertical * aspect, vertical * aspect,
        -vertical, vertical, .1, 10.);
    s.view->setViewport({0, 0, width, height});
}
void SpiritScene::update(const std::string& clip, int32_t serial, int32_t motionSerial, bool reduced, float x, float y) {
    auto& s = *impl_;
    if (!s.ready()) return;
    const auto known = s.clips.count(clip) ? clip : "idle_soft";
    if (s.serial != serial || s.requested != known || s.reduced != reduced) {
        s.requested = known; s.serial = serial; s.transition(known);
    }
    s.reduced = reduced;
    s.dragX = boundedInput(x); s.dragY = boundedInput(y);
    // Only a real reducer motion event refreshes the velocity-like input. A
    // redraw or unrelated recomposition must not revive a stale drag delta.
    if (s.motionSerial != motionSerial) {
        s.motionSerial = motionSerial;
        s.motionInputAge = 0.f;
    }
    if (reduced) {
        s.motionInputAge = 1.f;
        s.leanX = 0.f; s.leanY = 0.f;
        s.tailSignals.fill(0.f);
    }
}
void SpiritScene::pauseMotion() { impl_->motionInputAge = 1.f; }
bool SpiritScene::render(double deltaSeconds) {
    auto& s = *impl_;
    if (!s.ready() || !s.width || !s.height) return false;
    const float dt = std::isfinite(deltaSeconds) ? float(std::max(deltaSeconds, 0.)) : 0.f;
    if (!s.reduced) {
        s.time += dt;
        s.fade = std::min(1.f, s.fade + dt / .12f);
        s.motionInputAge += dt;
        const float targetX = s.motionInputAge <= .08f ? s.dragX : 0.f;
        const float targetY = s.motionInputAge <= .08f ? s.dragY : 0.f;
        const float blend = 1.f - std::exp(-dt * 12.f);
        s.leanX += (targetX - s.leanX) * blend;
        s.leanY += (targetY - s.leanY) * blend;
        advanceTail(s.tailSignals, -targetX, dt, false);
    } else {
        s.leanX = 0.f; s.leanY = 0.f;
        advanceTail(s.tailSignals, 0.f, 0.f, true);
    }
    auto& transforms = s.engine->getTransformManager();
    // Restore local transforms so partial animation channels and additive input
    // never accumulate drift over repeated taps, interruptions, or frame drops.
    for (const auto& entry : s.rest) transforms.setTransform(transforms.getInstance(entry.first), entry.second);
    const auto sample = sampleClip(s.current, s.time, s.reduced);
    const auto index = s.clips.at(sample.name);
    s.animator->applyAnimation(index, sample.seconds);
    if (!s.reduced && s.fade < 1.f && s.fadeFrom.size() == s.rest.size()) {
        const float alpha = smoothStep(s.fade);
        for (size_t i = 0; i < s.rest.size(); ++i) {
            const auto instance = transforms.getInstance(s.rest[i].first);
            float3 fromTranslation, fromScale, toTranslation, toScale;
            quatf fromRotation, toRotation;
            decomposeMatrix(s.fadeFrom[i], &fromTranslation, &fromRotation, &fromScale);
            decomposeMatrix(transforms.getTransform(instance), &toTranslation, &toRotation, &toScale);
            transforms.setTransform(instance, composeMatrix(mix(fromTranslation, toTranslation, alpha),
                normalize(fromRotation * (1.f-alpha) + toRotation * (dot(fromRotation,toRotation) < 0.f ? -alpha : alpha)), mix(fromScale, toScale, alpha)));
        }
    }
    // Snapshot the blended AUTHORED local pose before any procedural transform.
    // An interrupted transition must never add yesterday's tail offset twice.
    s.displayedPose.clear();
    for (const auto& entry : s.rest) {
        s.displayedPose.push_back(transforms.getTransform(transforms.getInstance(entry.first)));
    }
    if (!s.reduced) {
        for (size_t i = 0; i < s.tails.size(); ++i) {
            if (tailLimits[i] == 0.f) continue;
            const auto instance = transforms.getInstance(s.tails[i]);
            const auto& axis = tailAxes[i];
            transforms.setTransform(instance, transforms.getTransform(instance) *
                mat4f(quatf::fromAxisAngle(float3{axis[0], axis[1], axis[2]},
                    boundedInput(s.tailSignals[i]) * tailLimits[i])));
        }
    }
    transforms.setTransform(transforms.getInstance(s.asset->getRoot()), mat4f(quatf::fromAxisAngle(float3{0, 0, 1}, -s.leanX * .20943951f)));
    s.animator->updateBoneMatrices();
    const float targetOpening = eyeOpening(sample.name, sample.seconds);
    s.lastOpening = s.reduced ? targetOpening : s.fromOpening + (targetOpening - s.fromOpening) * smoothStep(s.fade);
    const auto weights = apertureWeights(s.lastOpening);
    auto& renderables = s.engine->getRenderableManager();
    // Sole eye owner, deliberately AFTER clip mixing and bone updates.
    for (Entity eye : s.eyes) renderables.setMorphWeights(renderables.getInstance(eye), weights.data(), weights.size());
    if (!s.renderer->beginFrame(s.swapChain)) return false;
    s.renderer->render(s.view);
    s.renderer->endFrame();
    return true;
}
} // namespace chur
