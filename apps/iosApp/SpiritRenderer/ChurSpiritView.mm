#import "ChurSpiritView.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <QuartzCore/CADisplayLink.h>
#include "SpiritScene.hpp"
#include <algorithm>
#include <cmath>
#include <exception>
#include <memory>

@class ChurSpiritView;
@interface ChurSpiritDisplayLinkTarget : NSObject
@property(nonatomic, weak) ChurSpiritView *owner;
- (void)tick:(CADisplayLink *)link;
- (void)visibilityTick:(NSTimer *)timer;
@end

@interface ChurSpiritView () {
    std::unique_ptr<chur::SpiritScene> _scene;
    CADisplayLink *_displayLink;
    NSTimer *_visibilityTimer;
    ChurSpiritDisplayLinkTarget *_displayTarget;
    CFTimeInterval _lastTimestamp;
    BOOL _disposed, _reducedMotion, _needsFrame, _suspended;
    UIView *_fallback;
}
- (void)tick:(CADisplayLink *)link;
- (void)refreshActivity;
- (void)stopDisplayLink;
- (BOOL)canRender;
- (BOOL)hostActive;
- (BOOL)hierarchyVisible;
- (void)stopVisibilityTimer;
@end

@implementation ChurSpiritDisplayLinkTarget
- (void)tick:(CADisplayLink *)link { [self.owner tick:link]; }
- (void)visibilityTick:(NSTimer *)timer { [self.owner refreshActivity]; }
@end

@implementation ChurSpiritView
+ (Class)layerClass { return [CAMetalLayer class]; }

- (instancetype)initWithModelURL:(NSURL *)url fallbackImage:(UIImage *)image {
    self = [super initWithFrame:CGRectZero];
    if (!self) return nil;
    NSAssert(NSThread.isMainThread, @"Spirit rendering is main-thread confined.");
    self.opaque = NO;
    self.backgroundColor = UIColor.clearColor;
    self.userInteractionEnabled = NO; // Compose owns tap, hold and drag gestures.
    self.isAccessibilityElement = NO; // Compose owns the single accessibility element.
    self.accessibilityElementsHidden = YES;
    self.clipsToBounds = NO;
    CAMetalLayer *metal = (CAMetalLayer *)self.layer;
    metal.opaque = NO;
    metal.pixelFormat = MTLPixelFormatBGRA8Unorm;
    metal.framebufferOnly = YES;
    metal.presentsWithTransaction = NO;
    metal.maximumDrawableCount = 3;
    NSData *data = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:nil];
    NSString *failure = nil;
    @try {
        try {
            _scene = std::make_unique<chur::SpiritScene>((__bridge void *)metal,
                static_cast<const uint8_t *>(data.bytes), data.length);
            if (!_scene->ready()) failure = [NSString stringWithUTF8String:_scene->error().c_str()];
        } catch (const std::exception& error) {
            failure = [NSString stringWithUTF8String:error.what()];
        }
    } @catch (NSException *exception) { failure = exception.reason; }
    if (failure || !_scene || !_scene->ready()) {
        NSLog(@"Chur spirit renderer: %@", failure ?: @"Initialization failed");
        _scene.reset();
        if (image) {
            UIImageView *poster = [[UIImageView alloc] initWithImage:image];
            poster.contentMode = UIViewContentModeScaleAspectFit;
            _fallback = poster;
        } else {
            UILabel *label = [[UILabel alloc] initWithFrame:CGRectZero];
            label.text = @"Chur";
            label.textColor = UIColor.secondaryLabelColor;
            label.textAlignment = NSTextAlignmentCenter;
            _fallback = label;
        }
        _fallback.userInteractionEnabled = NO;
        _fallback.accessibilityElementsHidden = YES;
        [self addSubview:_fallback];
    }
    _needsFrame = YES;
    _displayTarget = [ChurSpiritDisplayLinkTarget new];
    _displayTarget.owner = self;
    NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
    [center addObserver:self selector:@selector(willResignActive:) name:UIApplicationWillResignActiveNotification object:nil];
    [center addObserver:self selector:@selector(didBecomeActive:) name:UIApplicationDidBecomeActiveNotification object:nil];
    // Scene-level notifications matter for iPad multi-window transitions.
    [center addObserver:self selector:@selector(willResignActive:) name:UISceneWillDeactivateNotification object:nil];
    [center addObserver:self selector:@selector(didBecomeActive:) name:UISceneDidActivateNotification object:nil];
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    _fallback.frame = self.bounds;
    if (_disposed || !_scene) return;
    // Cap at 2x and 1024px: a small decorative surface should not allocate a
    // full iPad-sized HDR buffer when a window is resized.
    const CGFloat pointWidth = CGRectGetWidth(self.bounds), pointHeight = CGRectGetHeight(self.bounds);
    if (pointWidth <= 0 || pointHeight <= 0) { [self stopDisplayLink]; return; }
    const CGFloat displayScale = self.window.screen.scale ?: UIScreen.mainScreen.scale;
    const CGFloat scale = std::min({displayScale, CGFloat(2.), CGFloat(1024.) / std::max(pointWidth, pointHeight)});
    CAMetalLayer *metal = (CAMetalLayer *)self.layer;
    metal.contentsScale = scale;
    const CGSize drawable = CGSizeMake(std::max(1., std::round(pointWidth * scale)),
        std::max(1., std::round(pointHeight * scale)));
    if (!CGSizeEqualToSize(drawable, metal.drawableSize)) {
        metal.drawableSize = drawable;
        _needsFrame = YES;
    }
    _scene->resize(uint32_t(drawable.width), uint32_t(drawable.height));
    [self refreshActivity];
}

- (void)updateClip:(NSString *)clip serial:(int32_t)serial motionSerial:(int32_t)motionSerial
     reducedMotion:(BOOL)reducedMotion
            dragX:(float)dragX dragY:(float)dragY {
    NSAssert(NSThread.isMainThread, @"Spirit rendering is main-thread confined.");
    if (_disposed || !_scene) return;
    _reducedMotion = reducedMotion;
    _scene->update(clip.UTF8String ?: "idle_soft", serial, motionSerial, reducedMotion, dragX, dragY);
    _needsFrame = YES;
    [self refreshActivity];
}
- (BOOL)hostActive {
    return !_disposed && !_suspended && _scene && self.window &&
        CGRectGetWidth(self.bounds) > 0 && CGRectGetHeight(self.bounds) > 0 &&
        UIApplication.sharedApplication.applicationState == UIApplicationStateActive &&
        (!self.window.windowScene || self.window.windowScene.activationState == UISceneActivationStateForegroundActive);
}
- (BOOL)hierarchyVisible {
    if (!self.window || self.window.hidden || self.window.alpha <= 0) return NO;
    // Compose moves or clips the interop view without hiding it; skip frames nobody can see.
    CGRect visible = [self convertRect:self.bounds toView:nil];
    for (UIView *node = self; node; node = node.superview) {
        if (node.hidden || node.alpha <= 0) return NO;
        if (node != self && node.clipsToBounds) visible = CGRectIntersection(visible, [node convertRect:node.bounds toView:nil]);
    }
    return !CGRectIsEmpty(CGRectIntersection(visible, self.window.bounds));
}
- (BOOL)canRender { return [self hostActive] && [self hierarchyVisible]; }
- (void)stopVisibilityTimer { [_visibilityTimer invalidate]; _visibilityTimer = nil; }
- (void)refreshActivity {
    if (![self hostActive]) { [self stopDisplayLink]; [self stopVisibilityTimer]; return; }
    if (![self hierarchyVisible]) {
        [self stopDisplayLink];
        // UIKit does not guarantee ancestor hidden/alpha KVO. Poll only while
        // attached+active but hierarchy-hidden, so resuming cannot be missed.
        if (!_visibilityTimer) {
            _visibilityTimer = [NSTimer timerWithTimeInterval:.2 target:_displayTarget
                selector:@selector(visibilityTick:) userInfo:nil repeats:YES];
            [NSRunLoop.mainRunLoop addTimer:_visibilityTimer forMode:NSRunLoopCommonModes];
        }
        return;
    }
    if (_visibilityTimer) { [self stopVisibilityTimer]; _needsFrame = YES; }
    if (_reducedMotion && !_needsFrame) { [self stopDisplayLink]; return; }
    if (_displayLink) return;
    _lastTimestamp = 0;
    _displayLink = [CADisplayLink displayLinkWithTarget:_displayTarget selector:@selector(tick:)];
    _displayLink.preferredFramesPerSecond = 30;
    [_displayLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
}
- (void)stopDisplayLink {
    if (_scene) _scene->pauseMotion();
    [_displayLink invalidate];
    _displayLink = nil;
    _lastTimestamp = 0; // Background time must never advance the pose clock.
}
- (void)tick:(CADisplayLink *)link {
    if (![self canRender]) { [self refreshActivity]; return; }
    const double dt = _lastTimestamp == 0 ? 0 : link.timestamp - _lastTimestamp;
    _lastTimestamp = link.timestamp;
    if (_scene->render(dt)) _needsFrame = NO;
    // Reduced Motion gets exactly one successful dirty frame, then no clock.
    if (_reducedMotion && !_needsFrame) [self stopDisplayLink];
}
- (void)didMoveToWindow {
    [super didMoveToWindow];
    // Notifications can be missed while detached or when moving between scenes.
    // canRender rechecks current application/scene activation on every frame.
    _suspended = NO;
    _needsFrame = YES;
    [self setNeedsLayout];
    [self refreshActivity];
}
- (void)setHidden:(BOOL)hidden { [super setHidden:hidden]; [self refreshActivity]; }
- (void)setAlpha:(CGFloat)alpha { [super setAlpha:alpha]; [self refreshActivity]; }
- (void)willResignActive:(NSNotification *)notification {
    if ([notification.object isKindOfClass:UIScene.class] && notification.object != self.window.windowScene) return;
    _suspended = YES;
    [self refreshActivity];
}
- (void)didBecomeActive:(NSNotification *)notification {
    if ([notification.object isKindOfClass:UIScene.class] && notification.object != self.window.windowScene) return;
    _suspended = NO;
    _needsFrame = YES;
    [self refreshActivity];
}
- (void)dispose {
    NSAssert(NSThread.isMainThread, @"Spirit disposal is main-thread confined.");
    if (_disposed) return;
    _disposed = YES;
    [self stopDisplayLink];
    [self stopVisibilityTimer];
    [NSNotificationCenter.defaultCenter removeObserver:self];
    _displayTarget.owner = nil;
    _scene.reset();
}
- (void)dealloc { [self dispose]; }
@end
