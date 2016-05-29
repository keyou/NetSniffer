# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: EasiNet.Protocol.Common.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)




DESCRIPTOR = _descriptor.FileDescriptor(
  name='EasiNet.Protocol.Common.proto',
  package='EasiNet.Network.Protocols',
  serialized_pb='\n\x1d\x45\x61siNet.Protocol.Common.proto\x12\x19\x45\x61siNet.Network.Protocols\"0\n\tSlidePair\x12\x0f\n\x07SlideId\x18\x01 \x02(\t\x12\x12\n\nSlideIndex\x18\x02 \x02(\x05\"v\n\x0b\x45lementInfo\x12\x11\n\tElementId\x18\x01 \x02(\t\x12?\n\x0b\x45lementType\x18\x02 \x02(\x0e\x32*.EasiNet.Network.Protocols.ElementTypeEnum\x12\x13\n\x0b\x45lementData\x18\x03 \x02(\t*\xcb\x04\n\x0b\x43ommandEnum\x12\x0f\n\x0bNoneCommand\x10\x00\x12\x1c\n\x18\x43SAttenderConnectRequest\x10\x01\x12\x1d\n\x19SCAttenderConnectResponse\x10\x02\x12\x1a\n\x16SCAttendersInBroadcast\x10\x03\x12\x19\n\x15\x43SAttenderExitRequest\x10\x04\x12!\n\x1dSCAttenderDisConnectBroadcast\x10\x05\x12\x1b\n\x17SCAttendersOutBroadcast\x10\x06\x12\x12\n\x0e\x43SSlideRequest\x10\x07\x12\x13\n\x0fSCSlideResponse\x10\x08\x12\x19\n\x15SCElementsADUResponse\x10\t\x12\x0e\n\nSCResponse\x10\n\x12\x0c\n\x08InkStart\x10\x14\x12\n\n\x06Inking\x10\x15\x12\n\n\x06InkEnd\x10\x16\x12\x0e\n\nEraseStart\x10\x17\x12\x0b\n\x07\x45rasing\x10\x18\x12\x0c\n\x08\x45raseEnd\x10\x19\x12\x0f\n\x0bSelectStart\x10\x1a\x12\r\n\tSelecting\x10\x1b\x12\r\n\tSelectEnd\x10\x1c\x12\r\n\tMoveStart\x10\x1d\x12\n\n\x06Moving\x10\x1e\x12\x0b\n\x07MoveEnd\x10\x1f\x12\x0c\n\x08NewBoard\x10<\x12\x0c\n\x08\x41\x64\x64Slide\x10=\x12\x0f\n\x0bUpdateSlide\x10>\x12\r\n\tGoToSlide\x10?\x12\x0c\n\x08\x44\x65lSlide\x10@\x12\x0e\n\nAddElement\x10\x46\x12\x11\n\rUpdateElement\x10G\x12\x0e\n\nDelElement\x10H*\xfc\x02\n\rErrorCodeEnum\x12\x0c\n\x08NoneInit\x10\x00\x12\x0b\n\x07Success\x10\x01\x12\x17\n\x13SuccessConnectToNew\x10\n\x12\x14\n\x10SuccessAutoMerge\x10\x14\x12\t\n\x05\x45rror\x10\x64\x12\x11\n\rErrorConflict\x10\x65\x12\x18\n\x14\x45rrorNotAuthenticate\x10\x66\x12\x1b\n\x17\x45rrorAuthenticateFailed\x10g\x12\x1c\n\x18\x45rrorAlreadyAuthenticate\x10h\x12\x1d\n\x19\x45rrorAlreadyExistAttentId\x10i\x12\x1a\n\x16\x45rrorParseProtoPackage\x10j\x12\x19\n\x15\x45rrorDataNotAvailable\x10k\x12\x18\n\x14\x45rrorNotExistSlideId\x10l\x12\x1d\n\x19\x45rrorAddAlreadyExistSlide\x10m\x12\x1f\n\x1b\x45rrorNotAvailableSlideIndex\x10n*G\n\x0f\x45lementTypeEnum\x12\x13\n\x0fNoneElementType\x10\x00\x12\x07\n\x03Ink\x10\x01\x12\x0b\n\x07Picture\x10\x02\x12\t\n\x05Video\x10\x03*F\n\x0e\x44\x65viceTypeEnum\x12\x12\n\x0eNoneDeviceType\x10\x00\x12\t\n\x05Mouse\x10\x01\x12\n\n\x06Stylus\x10\x02\x12\t\n\x05Touch\x10\x03')

_COMMANDENUM = _descriptor.EnumDescriptor(
  name='CommandEnum',
  full_name='EasiNet.Network.Protocols.CommandEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NoneCommand', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CSAttenderConnectRequest', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCAttenderConnectResponse', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCAttendersInBroadcast', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CSAttenderExitRequest', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCAttenderDisConnectBroadcast', index=5, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCAttendersOutBroadcast', index=6, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CSSlideRequest', index=7, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCSlideResponse', index=8, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCElementsADUResponse', index=9, number=9,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCResponse', index=10, number=10,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='InkStart', index=11, number=20,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Inking', index=12, number=21,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='InkEnd', index=13, number=22,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='EraseStart', index=14, number=23,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Erasing', index=15, number=24,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='EraseEnd', index=16, number=25,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SelectStart', index=17, number=26,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Selecting', index=18, number=27,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SelectEnd', index=19, number=28,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MoveStart', index=20, number=29,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Moving', index=21, number=30,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MoveEnd', index=22, number=31,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NewBoard', index=23, number=60,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AddSlide', index=24, number=61,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UpdateSlide', index=25, number=62,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GoToSlide', index=26, number=63,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DelSlide', index=27, number=64,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AddElement', index=28, number=70,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UpdateElement', index=29, number=71,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DelElement', index=30, number=72,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=231,
  serialized_end=818,
)

CommandEnum = enum_type_wrapper.EnumTypeWrapper(_COMMANDENUM)
_ERRORCODEENUM = _descriptor.EnumDescriptor(
  name='ErrorCodeEnum',
  full_name='EasiNet.Network.Protocols.ErrorCodeEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NoneInit', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Success', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SuccessConnectToNew', index=2, number=10,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SuccessAutoMerge', index=3, number=20,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Error', index=4, number=100,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorConflict', index=5, number=101,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorNotAuthenticate', index=6, number=102,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorAuthenticateFailed', index=7, number=103,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorAlreadyAuthenticate', index=8, number=104,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorAlreadyExistAttentId', index=9, number=105,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorParseProtoPackage', index=10, number=106,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorDataNotAvailable', index=11, number=107,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorNotExistSlideId', index=12, number=108,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorAddAlreadyExistSlide', index=13, number=109,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ErrorNotAvailableSlideIndex', index=14, number=110,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=821,
  serialized_end=1201,
)

ErrorCodeEnum = enum_type_wrapper.EnumTypeWrapper(_ERRORCODEENUM)
_ELEMENTTYPEENUM = _descriptor.EnumDescriptor(
  name='ElementTypeEnum',
  full_name='EasiNet.Network.Protocols.ElementTypeEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NoneElementType', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Ink', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Picture', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Video', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1203,
  serialized_end=1274,
)

ElementTypeEnum = enum_type_wrapper.EnumTypeWrapper(_ELEMENTTYPEENUM)
_DEVICETYPEENUM = _descriptor.EnumDescriptor(
  name='DeviceTypeEnum',
  full_name='EasiNet.Network.Protocols.DeviceTypeEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NoneDeviceType', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Mouse', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Stylus', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Touch', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1276,
  serialized_end=1346,
)

DeviceTypeEnum = enum_type_wrapper.EnumTypeWrapper(_DEVICETYPEENUM)
NoneCommand = 0
CSAttenderConnectRequest = 1
SCAttenderConnectResponse = 2
SCAttendersInBroadcast = 3
CSAttenderExitRequest = 4
SCAttenderDisConnectBroadcast = 5
SCAttendersOutBroadcast = 6
CSSlideRequest = 7
SCSlideResponse = 8
SCElementsADUResponse = 9
SCResponse = 10
InkStart = 20
Inking = 21
InkEnd = 22
EraseStart = 23
Erasing = 24
EraseEnd = 25
SelectStart = 26
Selecting = 27
SelectEnd = 28
MoveStart = 29
Moving = 30
MoveEnd = 31
NewBoard = 60
AddSlide = 61
UpdateSlide = 62
GoToSlide = 63
DelSlide = 64
AddElement = 70
UpdateElement = 71
DelElement = 72
NoneInit = 0
Success = 1
SuccessConnectToNew = 10
SuccessAutoMerge = 20
Error = 100
ErrorConflict = 101
ErrorNotAuthenticate = 102
ErrorAuthenticateFailed = 103
ErrorAlreadyAuthenticate = 104
ErrorAlreadyExistAttentId = 105
ErrorParseProtoPackage = 106
ErrorDataNotAvailable = 107
ErrorNotExistSlideId = 108
ErrorAddAlreadyExistSlide = 109
ErrorNotAvailableSlideIndex = 110
NoneElementType = 0
Ink = 1
Picture = 2
Video = 3
NoneDeviceType = 0
Mouse = 1
Stylus = 2
Touch = 3



_SLIDEPAIR = _descriptor.Descriptor(
  name='SlidePair',
  full_name='EasiNet.Network.Protocols.SlidePair',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='SlideId', full_name='EasiNet.Network.Protocols.SlidePair.SlideId', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='SlideIndex', full_name='EasiNet.Network.Protocols.SlidePair.SlideIndex', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=60,
  serialized_end=108,
)


_ELEMENTINFO = _descriptor.Descriptor(
  name='ElementInfo',
  full_name='EasiNet.Network.Protocols.ElementInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ElementId', full_name='EasiNet.Network.Protocols.ElementInfo.ElementId', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ElementType', full_name='EasiNet.Network.Protocols.ElementInfo.ElementType', index=1,
      number=2, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ElementData', full_name='EasiNet.Network.Protocols.ElementInfo.ElementData', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=110,
  serialized_end=228,
)

_ELEMENTINFO.fields_by_name['ElementType'].enum_type = _ELEMENTTYPEENUM
DESCRIPTOR.message_types_by_name['SlidePair'] = _SLIDEPAIR
DESCRIPTOR.message_types_by_name['ElementInfo'] = _ELEMENTINFO

class SlidePair(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _SLIDEPAIR

  # @@protoc_insertion_point(class_scope:EasiNet.Network.Protocols.SlidePair)

class ElementInfo(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _ELEMENTINFO

  # @@protoc_insertion_point(class_scope:EasiNet.Network.Protocols.ElementInfo)


# @@protoc_insertion_point(module_scope)