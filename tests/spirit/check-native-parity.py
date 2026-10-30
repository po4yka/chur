#!/usr/bin/env python3
"""Execute production Kotlin/C++ clip, eye, tail and pose math. No GPU/native host claim."""
import json
import math
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
filament = root / 'apps/iosApp/SpiritRenderer/.vendor/filament/include'


def kotlin_lib() -> pathlib.Path:
    if os.environ.get('KOTLIN_COMPILER_LIB'):
        return pathlib.Path(os.environ['KOTLIN_COMPILER_LIB'])
    kotlinc = shutil.which('kotlinc')
    if kotlinc:
        home = pathlib.Path(kotlinc).resolve().parent.parent
        for lib in (home / 'lib', home / 'libexec/lib'):
            if lib.is_dir():
                return lib
    sys.exit('Kotlin compiler not found: install kotlinc or set KOTLIN_COMPILER_LIB to its lib directory.')


compiler = kotlin_lib()
stdlib = next((j for pattern in ('kotlin-stdlib.jar', 'kotlin-stdlib-[0-9]*.jar') for j in compiler.glob(pattern)), None)
if stdlib is None:
    sys.exit(f'No kotlin-stdlib jar in {compiler}.')
if not (filament / 'gltfio/math.h').is_file():
    sys.exit('Filament headers are missing: run apps/iosApp/SpiritRenderer/prepare-filament.sh first.')

# Unknown names must fall back identically on both sides.
clips = ['idle_soft', 'notice', 'tap_react', 'hold_enter', 'hold_loop', 'release_settle', 'sleep_enter', 'sleep_loop', 'wake', 'unknown_clip']


def trs(t, axis, angle, s):
    """Column-major TRS input matrix (positive scale, as the bundled asset uses)."""
    n = math.sqrt(sum(a * a for a in axis))
    x, y, z = (a / n * math.sin(angle / 2) for a in axis)
    w = math.cos(angle / 2)
    r = [[1 - 2 * (y * y + z * z), 2 * (x * y + z * w), 2 * (x * z - y * w)],
         [2 * (x * y - z * w), 1 - 2 * (x * x + z * z), 2 * (y * z + x * w)],
         [2 * (x * z + y * w), 2 * (y * z - x * w), 1 - 2 * (x * x + y * y)]]
    m = [0.0] * 16
    for col in range(3):
        for row in range(3):
            m[col * 4 + row] = r[col][row] * s[col]
    m[12:15] = t
    m[15] = 1.0
    return m


poses = [
    (trs([0, 0, 0], [0, 0, 1], 0.0, [1, 1, 1]), trs([0.5, -0.25, 1], [0, 1, 0], 1.2, [1, 1, 1])),
    (trs([1, 2, -1], [1, 1, 0], 0.4, [0.5, 1.5, 2]), trs([-1, 0, 0.5], [0, 1, 1], -2.1, [2, 0.75, 1])),
    # More than half a turn apart: the shorter arc needs the quaternion sign flip.
    (trs([0, 0, 0], [0, 0, 1], 0.1, [1, 1, 1]), trs([0, 0, 0], [0, 0, 1], 3.0, [1, 1, 1])),
]
alphas = [0.0, 0.25, 0.5, 0.75, 1.0]


def floats(values, suffix):
    return ','.join(repr(float(v)) + suffix for v in values)


kotlin_poses = ',\n  '.join(f'floatArrayOf({floats(a, "f")}) to floatArrayOf({floats(b, "f")})' for a, b in poses)
cpp_poses = ',\n  '.join(f'{{{{ {floats(a, "f")} }}, {{ {floats(b, "f")} }}}}' for a, b in poses)
clip_list = ','.join('"' + c + '"' for c in clips)

with tempfile.TemporaryDirectory() as tmp:
    t = pathlib.Path(tmp)
    (t / 'Parity.kt').write_text(f'''import dev.po4yka.chur.app.spirit.*
fun main() {{
 for (reduced in listOf(false, true)) for (clip in listOf({clip_list})) for (hz in listOf(30,60,120)) for (frame in 0..hz*5) {{
  val sample = sampleSpiritClip(clip, frame.toFloat()/hz, reduced)
  val opening = SpiritEyes.aperture(sample, reduced)
  println("$reduced/$clip/$hz/$frame ${{sample.name}} ${{sample.seconds}} $opening " + SpiritEyes.weights(opening).joinToString(" "))
 }}
 for (hz in listOf(30,60,120)) {{ var tail = FloatArray(8); for (frame in 0..hz*3) {{
  tail = advanceSpiritTail(tail, if (frame < hz) 1f else 0f, 1f/hz, false)
  println("tail/$hz/$frame tail " + tail.joinToString(" "))
 }}}}
 // Oversized steps, non-finite input and reduced motion.
 var edge = FloatArray(8)
 for ((step, entry) in listOf(.5f to 1f, .1f to Float.NaN, .1f to 3f, .1f to -1f).withIndex()) {{
  edge = advanceSpiritTail(edge, entry.second, entry.first, step == 3)
  println("tail-edge/$step tail " + edge.joinToString(" "))
 }}
 for ((index, pose) in listOf(
  {kotlin_poses}).withIndex()) for ((step, alpha) in listOf({floats(alphas, "f")}).withIndex())
  println("pose/$index/$step pose " + blendSpiritPose(pose.first, pose.second, alpha).joinToString(" "))
}}''')
    (t / 'parity.cpp').write_text(f'''#include "SpiritMotion.hpp"
#include "SpiritPose.hpp"
#include "SpiritTail.hpp"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
const char* flag(bool v) {{ return v ? "true" : "false"; }}
int main() {{ using namespace chur; std::cout << std::setprecision(9);
 for (bool reduced : {{false, true}}) for (auto clip : {{{clip_list}}}) for (int hz : {{30,60,120}}) for (int frame = 0; frame <= hz*5; frame++) {{
  auto sample = sampleClip(clip, float(frame)/hz, reduced); auto opening = eyeOpening(sample.name, sample.seconds);
  std::cout << flag(reduced) << "/" << clip << "/" << hz << "/" << frame << " " << sample.name << " " << sample.seconds << " " << opening;
  for (auto w : apertureWeights(opening)) std::cout << " " << w; std::cout << "\\n";
 }}
 for (int hz : {{30,60,120}}) {{ std::array<float,8> tail{{}}; for (int frame = 0; frame <= hz*3; frame++) {{
  advanceTail(tail, frame < hz ? 1.f : 0.f, 1.f/hz, false); std::cout << "tail/" << hz << "/" << frame << " tail"; for (auto w : tail) std::cout << " " << w; std::cout << "\\n"; }}}}
 std::array<float,8> edge{{}};
 const float steps[4][2] = {{{{.5f, 1.f}}, {{.1f, std::numeric_limits<float>::quiet_NaN()}}, {{.1f, 3.f}}, {{.1f, -1.f}}}};
 for (int step = 0; step < 4; step++) {{
  advanceTail(edge, steps[step][1], steps[step][0], step == 3); std::cout << "tail-edge/" << step << " tail"; for (auto w : edge) std::cout << " " << w; std::cout << "\\n"; }}
 const float poses[][2][16] = {{
  {cpp_poses} }};
 const float alphas[] = {{{floats(alphas, "f")}}};
 for (int index = 0; index < int(sizeof(poses)/sizeof(poses[0])); index++) for (int step = 0; step < int(sizeof(alphas)/sizeof(alphas[0])); step++) {{
  filament::math::mat4f from, to;
  for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) {{ from[c][r] = poses[index][0][c*4+r]; to[c][r] = poses[index][1][c*4+r]; }}
  auto out = blendPose(from, to, alphas[step]);
  std::cout << "pose/" << index << "/" << step << " pose"; for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) std::cout << " " << out[c][r]; std::cout << "\\n";
 }}
}}''')
    common = root / 'shared/app/src/commonMain/kotlin/dev/po4yka/chur/app/spirit'
    subprocess.run(['java', '-Xmx256m', '-cp', str(compiler / '*'), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-classpath', str(stdlib),
                    *[str(common / (n + '.kt')) for n in ['SpiritAnimation', 'SpiritTail', 'SpiritPose']], str(t / 'Parity.kt'), '-d', str(t / 'parity.jar')], check=True)
    subprocess.run(['c++', '-std=c++17', '-O0', '-I', str(root / 'apps/iosApp/SpiritRenderer'), '-I', str(filament), str(t / 'parity.cpp'), '-o', str(t / 'parity')], check=True)
    kotlin = subprocess.check_output(['java', '-cp', f'{t}/parity.jar:{stdlib}', 'ParityKt'], text=True).splitlines()
    cpp = subprocess.check_output([str(t / 'parity')], text=True).splitlines()
    assert len(kotlin) == len(cpp), (len(kotlin), len(cpp))
    maximum = 0.0
    for a, b in zip(kotlin, cpp):
        a, b = a.split(), b.split()
        assert len(a) == len(b) and a[:2] == b[:2], (a, b)
        for x, y in zip(a[2:], b[2:]):
            delta = abs(float(x) - float(y))
            maximum = max(maximum, delta)
            assert delta < 5e-5, (a, b, delta)
    print(json.dumps({'status': 'PASS', 'production_math_sample_pairs': len(kotlin), 'max_abs_error': maximum, 'rates_hz': [30, 60, 120], 'gpu_or_host_validated': False}))
