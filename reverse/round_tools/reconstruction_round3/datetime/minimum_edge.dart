import 'dart:io';
void main(){for(var s in ['-290308-12-21T19:59:05.224192','-290308-12-21T19:59:05.224192Z']){try{print(DateTime.parse(s));}catch(e,st){print('$s\n${e.runtimeType}: $e\n$st');}}}
