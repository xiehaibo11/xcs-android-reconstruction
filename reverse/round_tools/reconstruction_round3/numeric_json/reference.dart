import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

void main(List<String> args) {
  final cases=jsonDecode(File(args[0]).readAsStringSync()) as List;
  final out=File(args[1]).openWrite();
  for(final c in cases) {
    final mode=c[0] as String,source=c[1] as String;
    final prefix='$mode\t${base64Encode(utf8.encode(source))}\t';
    try {
      dynamic n=jsonDecode(source);
      if(mode=='array')n=n[0]; else if(mode=='object')n=n['n'];
      if(n is int)out.writeln('${prefix}int\t$n\tfinite');
      else if(n is double){
        final data=ByteData(8)..setFloat64(0,n);
        final bits=data.buffer.asUint8List().map((b)=>b.toRadixString(16).padLeft(2,'0')).join();
        var encodable=true;try{jsonEncode(n);}catch(_){encodable=false;}
        out.writeln('${prefix}double\t$bits\t${encodable?'finite':'nonfinite'}');
      }else{throw StateError('Numeric fixture produced non-number');}
    }on FormatException {out.writeln('${prefix}error\tFormatException\t-');}
  }
  out.close();
}
