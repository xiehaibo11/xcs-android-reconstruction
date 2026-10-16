import 'dart:convert';
import 'dart:io';
// Official 3.5.2 SDK reference execution, never the original APK.
void main() {
  while(true){
    final line=stdin.readLineSync();if(line==null)break;
    final input=utf8.decode(base64.decode(line));
    try{final d=DateTime.parse(input);stdout.writeln('ok\t${d.microsecondsSinceEpoch}\t${d.millisecondsSinceEpoch}\t${d.toIso8601String()}\t${d.toString()}\t${d.isUtc}');}
    on FormatException catch(e){stdout.writeln('error\tFormatException\t${e.message}');}
    catch(e){stdout.writeln('error\t${e.runtimeType}\tother');}
  }
}
