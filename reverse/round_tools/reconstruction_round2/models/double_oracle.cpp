#include "double-conversion.h"
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
int main(){
  using double_conversion::DoubleToStringConverter;
  DoubleToStringConverter convert(DoubleToStringConverter::EMIT_POSITIVE_EXPONENT_SIGN |
      DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT | DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT,
      "Infinity","NaN",'e',-6,21,0,0);
  std::string input;
  while(std::cin>>input){uint64_t bits=std::stoull(input,nullptr,16);double value;std::memcpy(&value,&bits,8);
    char output[128];double_conversion::StringBuilder builder(output,128);
    if(!convert.ToShortest(value,&builder))return 1;
    std::cout<<builder.Finalize()<<'\n';
  }
}
