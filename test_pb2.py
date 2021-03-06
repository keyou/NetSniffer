# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: test.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)




DESCRIPTOR = _descriptor.FileDescriptor(
  name='test.proto',
  package='EasiNet.Protocol',
  serialized_pb='\n\ntest.proto\x12\x10\x45\x61siNet.Protocol\"\xa3\x01\n\x07\x43ommand\x12\x11\n\tContextId\x18\x01 \x01(\x0c\x12.\n\x07MainCmd\x18\x02 \x02(\x0e\x32\x1d.EasiNet.Protocol.MainCmdEnum\x12,\n\x06SubCmd\x18\x03 \x02(\x0e\x32\x1c.EasiNet.Protocol.SubCmdEnum\x12\x13\n\x0bMainCmdArgs\x18\x04 \x01(\x0c\x12\x12\n\nSubCmdArgs\x18\x05 \x01(\x0c\"\r\n\x0bPushEndArgs\"Y\n\x0cInkStartArgs\x12\t\n\x01X\x18\x01 \x02(\x05\x12\t\n\x01Y\x18\x02 \x02(\x05\x12\x11\n\tElementId\x18\x03 \x02(\t\x12\x10\n\x08\x43lientId\x18\x04 \x02(\t\x12\x0e\n\x06\x45lment\x18\x05 \x02(\x0c\"G\n\nInkingArgs\x12\t\n\x01X\x18\x01 \x02(\x05\x12\t\n\x01Y\x18\x02 \x02(\x05\x12\x11\n\tElementId\x18\x03 \x02(\t\x12\x10\n\x08\x43lientId\x18\x04 \x02(\t\"G\n\nInkEndArgs\x12\t\n\x01X\x18\x01 \x02(\x05\x12\t\n\x01Y\x18\x02 \x02(\x05\x12\x11\n\tElementId\x18\x03 \x02(\t\x12\x10\n\x08\x43lientId\x18\x04 \x02(\t*N\n\x0bMainCmdEnum\x12\r\n\tPushStart\x10\x00\x12\x0f\n\x0bPushRequest\x10\x01\x12\x0b\n\x07PushEnd\x10\x02\x12\x12\n\x0ePatchBroadcast\x10\x03*Z\n\nSubCmdEnum\x12\r\n\tMoveStart\x10\x00\x12\n\n\x06Moving\x10\x01\x12\x0b\n\x07MoveEnd\x10\x02\x12\x0c\n\x08InkStart\x10\x03\x12\n\n\x06Inking\x10\x04\x12\n\n\x06InkEnd\x10\x05')

_MAINCMDENUM = _descriptor.EnumDescriptor(
  name='MainCmdEnum',
  full_name='EasiNet.Protocol.MainCmdEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PushStart', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PushRequest', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PushEnd', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PatchBroadcast', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=450,
  serialized_end=528,
)

MainCmdEnum = enum_type_wrapper.EnumTypeWrapper(_MAINCMDENUM)
_SUBCMDENUM = _descriptor.EnumDescriptor(
  name='SubCmdEnum',
  full_name='EasiNet.Protocol.SubCmdEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='MoveStart', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Moving', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MoveEnd', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='InkStart', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='Inking', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='InkEnd', index=5, number=5,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=530,
  serialized_end=620,
)

SubCmdEnum = enum_type_wrapper.EnumTypeWrapper(_SUBCMDENUM)
PushStart = 0
PushRequest = 1
PushEnd = 2
PatchBroadcast = 3
MoveStart = 0
Moving = 1
MoveEnd = 2
InkStart = 3
Inking = 4
InkEnd = 5



_COMMAND = _descriptor.Descriptor(
  name='Command',
  full_name='EasiNet.Protocol.Command',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ContextId', full_name='EasiNet.Protocol.Command.ContextId', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='MainCmd', full_name='EasiNet.Protocol.Command.MainCmd', index=1,
      number=2, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='SubCmd', full_name='EasiNet.Protocol.Command.SubCmd', index=2,
      number=3, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='MainCmdArgs', full_name='EasiNet.Protocol.Command.MainCmdArgs', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='SubCmdArgs', full_name='EasiNet.Protocol.Command.SubCmdArgs', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
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
  serialized_start=33,
  serialized_end=196,
)


_PUSHENDARGS = _descriptor.Descriptor(
  name='PushEndArgs',
  full_name='EasiNet.Protocol.PushEndArgs',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=198,
  serialized_end=211,
)


_INKSTARTARGS = _descriptor.Descriptor(
  name='InkStartArgs',
  full_name='EasiNet.Protocol.InkStartArgs',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='X', full_name='EasiNet.Protocol.InkStartArgs.X', index=0,
      number=1, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='Y', full_name='EasiNet.Protocol.InkStartArgs.Y', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ElementId', full_name='EasiNet.Protocol.InkStartArgs.ElementId', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ClientId', full_name='EasiNet.Protocol.InkStartArgs.ClientId', index=3,
      number=4, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='Elment', full_name='EasiNet.Protocol.InkStartArgs.Elment', index=4,
      number=5, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value="",
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
  serialized_start=213,
  serialized_end=302,
)


_INKINGARGS = _descriptor.Descriptor(
  name='InkingArgs',
  full_name='EasiNet.Protocol.InkingArgs',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='X', full_name='EasiNet.Protocol.InkingArgs.X', index=0,
      number=1, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='Y', full_name='EasiNet.Protocol.InkingArgs.Y', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ElementId', full_name='EasiNet.Protocol.InkingArgs.ElementId', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ClientId', full_name='EasiNet.Protocol.InkingArgs.ClientId', index=3,
      number=4, type=9, cpp_type=9, label=2,
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
  serialized_start=304,
  serialized_end=375,
)


_INKENDARGS = _descriptor.Descriptor(
  name='InkEndArgs',
  full_name='EasiNet.Protocol.InkEndArgs',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='X', full_name='EasiNet.Protocol.InkEndArgs.X', index=0,
      number=1, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='Y', full_name='EasiNet.Protocol.InkEndArgs.Y', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ElementId', full_name='EasiNet.Protocol.InkEndArgs.ElementId', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ClientId', full_name='EasiNet.Protocol.InkEndArgs.ClientId', index=3,
      number=4, type=9, cpp_type=9, label=2,
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
  serialized_start=377,
  serialized_end=448,
)

_COMMAND.fields_by_name['MainCmd'].enum_type = _MAINCMDENUM
_COMMAND.fields_by_name['SubCmd'].enum_type = _SUBCMDENUM
DESCRIPTOR.message_types_by_name['Command'] = _COMMAND
DESCRIPTOR.message_types_by_name['PushEndArgs'] = _PUSHENDARGS
DESCRIPTOR.message_types_by_name['InkStartArgs'] = _INKSTARTARGS
DESCRIPTOR.message_types_by_name['InkingArgs'] = _INKINGARGS
DESCRIPTOR.message_types_by_name['InkEndArgs'] = _INKENDARGS

class Command(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _COMMAND

  # @@protoc_insertion_point(class_scope:EasiNet.Protocol.Command)

class PushEndArgs(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _PUSHENDARGS

  # @@protoc_insertion_point(class_scope:EasiNet.Protocol.PushEndArgs)

class InkStartArgs(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _INKSTARTARGS

  # @@protoc_insertion_point(class_scope:EasiNet.Protocol.InkStartArgs)

class InkingArgs(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _INKINGARGS

  # @@protoc_insertion_point(class_scope:EasiNet.Protocol.InkingArgs)

class InkEndArgs(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _INKENDARGS

  # @@protoc_insertion_point(class_scope:EasiNet.Protocol.InkEndArgs)


# @@protoc_insertion_point(module_scope)
