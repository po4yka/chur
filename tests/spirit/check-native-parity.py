#!/usr/bin/env python3
"""Execute production Kotlin/C++ clip, eye and tail math. No GPU/native host claim."""
import os,pathlib,subprocess,tempfile,json
root=pathlib.Path(__file__).resolve().parents[2]
compiler=pathlib.Path(os.environ['KOTLIN_COMPILER_LIB'])
stdlib=next(compiler.glob('kotlin-stdlib-[0-9]*.jar'))
clips=['idle_soft','notice','tap_react','hold_enter','hold_loop','release_settle','sleep_enter','sleep_loop','wake']
with tempfile.TemporaryDirectory() as tmp:
 t=pathlib.Path(tmp)
 (t/'Parity.kt').write_text('''import dev.po4yka.chur.app.spirit.*
fun main() {
 for (clip in listOf('''+','.join('"'+c+'"' for c in clips)+''')) for(hz in listOf(30,60,120)) for(frame in 0..hz*5) {
  val sample=sampleSpiritClip(clip, frame.toFloat()/hz,false)
  val opening=SpiritEyes.aperture(sample,false)
  println("$clip/$hz/$frame ${sample.name} ${sample.seconds} $opening " + SpiritEyes.weights(opening).joinToString(" "))
 }
 for(hz in listOf(30,60,120)) { var tail=FloatArray(8); for(frame in 0..hz*3) {
  tail=advanceSpiritTail(tail, if(frame < hz) 1f else 0f,1f/hz,false)
  println("tail/$hz/$frame tail " + tail.joinToString(" "))
 }}
}''')
 (t/'parity.cpp').write_text('''#include "SpiritMotion.hpp"
#include "SpiritTail.hpp"
#include <iostream>
#include <iomanip>
int main(){ using namespace chur; std::cout<<std::setprecision(9);
 for(auto clip : {'''+','.join('"'+c+'"' for c in clips)+'''}) for(int hz:{30,60,120}) for(int frame=0;frame<=hz*5;frame++){
 auto sample=sampleClip(clip,float(frame)/hz,false); auto opening=eyeOpening(sample.name,sample.seconds);
 std::cout<<clip<<"/"<<hz<<"/"<<frame<<" "<<sample.name<<" "<<sample.seconds<<" "<<opening;
 for(auto w:apertureWeights(opening))std::cout<<" "<<w;std::cout<<"\\n";
 }
 for(int hz:{30,60,120}){std::array<float,8> tail{};for(int frame=0;frame<=hz*3;frame++){
 advanceTail(tail,frame<hz?1.f:0.f,1.f/hz,false);std::cout<<"tail/"<<hz<<"/"<<frame<<" tail";for(auto w:tail)std::cout<<" "<<w;std::cout<<"\\n";}}
}''')
 common=root/'shared/app/src/commonMain/kotlin/dev/po4yka/chur/app/spirit'
 subprocess.run(['java','-Xmx256m','-cp',str(compiler/'*'),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',str(stdlib),*[str(common/(n+'.kt')) for n in ['SpiritAnimation','SpiritTail']],str(t/'Parity.kt'),'-d',str(t/'parity.jar')],check=True)
 subprocess.run(['g++','-std=c++17','-O0','-I',str(root/'apps/iosApp/SpiritRenderer'),str(t/'parity.cpp'),'-o',str(t/'parity')],check=True)
 kotlin=subprocess.check_output(['java','-cp',f'{t}/parity.jar:{stdlib}','ParityKt'],text=True).splitlines()
 cpp=subprocess.check_output([str(t/'parity')],text=True).splitlines()
 assert len(kotlin)==len(cpp)
 maximum=0
 for a,b in zip(kotlin,cpp):
  a,b=a.split(),b.split();assert a[:2]==b[:2],(a,b)
  for x,y in zip(a[2:],b[2:]):
   delta=abs(float(x)-float(y));maximum=max(maximum,delta);assert delta<5e-5,(a,b,delta)
 print(json.dumps({'status':'PASS','production_math_sample_pairs':len(kotlin),'max_abs_error':maximum,'rates_hz':[30,60,120],'gpu_or_host_validated':False}))
