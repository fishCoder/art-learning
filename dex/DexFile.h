//
// Created by fulongbin on 2019-06-28.
//

#ifndef ART_LEARNING_DEXFILE_H
#define ART_LEARNING_DEXFILE_H

#include <vector>
#include "../base/base.h"

#define NO_INDEX 0xffffffff

typedef enum _access_flags {
    ACC_PUBLIC=0x1,
    ACC_PRIVATE=0x2,
    ACC_PROTECTED=0x4,
    ACC_STATIC=0x8,
    ACC_FINAL=0x10,
    ACC_SYNCHRONIZED=0x20,
    ACC_VOLATILE=0x40,
    ACC_BRIDGE=0x40,
    ACC_TRANSIENT=0x80,
    ACC_VARARGS=0x80,
    ACC_NATIVE=0x100,
    ACC_INTERFACE=0x200,
    ACC_ABSTRACT=0x400,
    ACC_STRICT=0x800,
    ACC_SYNTHETIC=0x1000,
    ACC_ANNOTATION=0x2000,
    ACC_ENUM=0x4000,
    ACC_CONSTRUCTOR=0x10000,
    ACC_DECLARED_SYNCHRONIZED=0x20000
} access_flag;


typedef enum _endian_tag_flag {
    ENDIAN_CONSTANT = 0x12345678,
    REVERSE_ENDIAN_CONSTANT = 0x78563412
} endian_tag_flag;

typedef struct dex_header_item {
    dex_ubyte magic[8];
    dex_uint checksum;
    dex_ubyte signature[20];
    dex_uint file_size;
    dex_uint header_size=0x70;
    dex_uint endian_tag=ENDIAN_CONSTANT;
    dex_uint link_size;
    dex_uint link_off;
    dex_uint map_off;
    dex_uint string_ids_size;
    dex_uint string_ids_off;
    dex_uint type_ids_size;
    dex_uint type_ids_off;
    dex_uint proto_ids_size;
    dex_uint proto_ids_off;
    dex_uint field_ids_size;
    dex_uint field_ids_off;
    dex_uint method_ids_size;
    dex_uint method_ids_off;
    dex_uint class_defs_size;
    dex_uint class_defs_off;
    dex_uint data_size;
    dex_uint data_off;
} header_item;

typedef enum _value_type {
    VALUE_BYTE = 0x00,
    VALUE_SHORT = 0x02,
    VALUE_CHAR = 0x03,
    VALUE_INT = 0x04,
    VALUE_LONG = 0x06,
    VALUE_FLOAT = 0x10,
    VALUE_DOUBLE = 0x11,
    VALUE_METHOD_TYPE = 0x15,
    VALUE_METHOD_HANDLE = 0x16,
    VALUE_STRING = 0x17,
    VALUE_TYPE = 0x18,
    VALUE_FIELD = 0x19,
    VALUE_METHOD = 0x1a,
    VALUE_ENUM = 0x1b,
    VALUE_ARRAY = 0x1c,
    VALUE_ANNOTATION = 0x1d,
    VALUE_NULL = 0x1e,
    VALUE_BOOLEAN = 0x1f
} dex_value_type;

struct dex_class_data_item;
typedef dex_class_data_item class_data_item;
struct dex_encoded_array;
typedef dex_encoded_array encoded_array;
struct dex_encoded_annotation;
typedef dex_encoded_annotation encoded_annotation;

typedef enum _map_item_type{
    TYPE_HEADER_ITEM = 0x0000,
    TYPE_STRING_ID_ITEM = 0x0001,
    TYPE_TYPE_ID_ITEM = 0x0002,
    TYPE_PROTO_ID_ITEM = 0x0003,
    TYPE_FIELD_ID_ITEM = 0x0004,
    TYPE_METHOD_ID_ITEM = 0x0005,
    TYPE_CLASS_DEF_ITEM = 0x0006,
    TYPE_CALL_SITE_ID_ITEM = 0x0007,
    TYPE_METHOD_HANDLE_ITEM = 0x0008,
    TYPE_MAP_LIST = 0x1000,
    TYPE_TYPE_LIST = 0x1001,
    TYPE_ANNOTATION_SET_REF_LIST = 0x1002,
    TYPE_ANNOTATION_SET_ITEM = 0x1003,
    TYPE_CLASS_DATA_ITEM = 0x2000,
    TYPE_CODE_ITEM = 0x2001,
    TYPE_STRING_DATA_ITEM = 0x2002,
    TYPE_DEBUG_INFO_ITEM = 0x2003,
    TYPE_ANNOTATION_ITEM = 0x2004,
    TYPE_ENCODED_ARRAY_ITEM = 0x2005,
    TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006
} map_item_type;

typedef struct dex_map_item {
    dex_ushort type;
    dex_ushort unused;
    dex_uint size;
    dex_uint offset;
} map_item;

typedef struct dex_map_list {
    dex_uint size;
    map_item *list;
} map_list;


typedef struct dex_string_id_item {
    dex_uint string_data_off;
} string_id_item;

typedef struct dex_string_data_item {
    dex_uint utf16_size;
    dex_ubyte *data;
} string_data_item;

typedef struct dex_type_id_item {
    dex_uint descriptor_idx;
} type_id_item;

typedef struct dex_type_item {
    dex_ushort type_idx;
} type_item;

typedef struct dex_type_list {
    dex_uint size;
    std::vector<dex_type_item> list;
} type_list;

typedef struct dex_proto_id_item {
    dex_uint shorty_idx;
    dex_uint return_type_idx;
    dex_uint parameters_off;
    type_list parameters_list;
} proto_id_item;


typedef struct dex_field_id_item {
    dex_ushort class_idx;
    dex_ushort type_idx;
    uint name_idx;
} field_id_item;

typedef struct dex_method_id_item {
    dex_ushort class_idx;
    dex_ushort proto_idx;
    uint name_idx;
} method_id_item;

typedef struct dex_class_def_item {
    dex_uint class_idx;
    dex_uint access_flags;
    dex_uint superclass_idx;
    dex_uint interfaces_off;
    type_list interfaces_list;
    dex_uint source_file_idx;
    dex_uint annotations_off;
    dex_uint class_data_off;
    std::shared_ptr<class_data_item> class_data;
    dex_uint static_values_off;
} class_def_item;


typedef struct dex_encoded_value {
    dex_ubyte value_type;
    dex_ubyte value_arg;
    std::vector<dex_ubyte> value;
    std::shared_ptr<encoded_array> encoded_array;
    std::shared_ptr<encoded_annotation> encoded_annotation;
} encoded_value;

typedef struct dex_encoded_array {
    dex_uint size;
    std::vector<encoded_value> values;
} encoded_array;

typedef struct dex_annotation_element {
    dex_uint name_idx;
    encoded_value value;
} annotation_element;

typedef struct dex_encoded_annotation {
    dex_uint type_idx;
    dex_uint size;
    std::vector<annotation_element> elements;
} encoded_annotation;

typedef struct dex_annotation_item {
    dex_ubyte  visibility;
    encoded_annotation annotation;
} annotation_item;

typedef struct dex_annotation_off_item {
    dex_uint annotation_off;
    annotation_item annotation;
} annotation_off_item;

typedef struct dex_annotation_set_item {
    dex_uint size;
    std::vector<annotation_off_item> entries;
} annotation_set_item;

typedef struct dex_annotation_set_ref_item {
    dex_uint annotations_off;
    annotation_set_item item;
} annotation_set_ref_item;

typedef struct dex_annotation_set_ref_list {
    dex_uint size;
    std::vector<annotation_set_ref_item> list;
} annotation_set_ref_list;

typedef struct dex_field_annotation {
    dex_uint field_idx;
    dex_uint annotations_off;
    annotation_set_item field_annotation;
} field_annotation;

typedef struct dex_method_annotation {
    dex_uint method_idx;
    dex_uint annotations_off;
    annotation_set_item method_annotations;
} method_annotation;

typedef struct dex_parameter_annotation {
    dex_uint method_idx;
    dex_uint annotations_off;
    annotation_set_ref_list parameter_annotations;
} parameter_annotation;

typedef struct dex_debug_info_item {
    dex_uint line_start;
    dex_uint parameters_size;
    std::vector<dex_uint> parameter_names;
} debug_info_item;

typedef struct dex_encoded_field {
    dex_uint field_idx_diff;
    dex_uint access_flags;
} encoded_field;

typedef struct dex_try_item {
    dex_uint start_addr;
    dex_ushort insn_count;
    dex_ushort handler_off;
} try_item;

typedef struct dex_encoded_type_addr_pair {
    dex_uint type_idx;
    dex_uint addr;
} encoded_type_addr_pair;

typedef struct dex_encoded_catch_handler {
    dex_uint size;
    std::vector<encoded_type_addr_pair> handlers;
    dex_uint catch_all_addr;
} encoded_catch_handler;

typedef struct dex_encoded_catch_handler_list {
    dex_uint size;
    std::vector<encoded_catch_handler> list;
} encoded_catch_handler_list;


typedef struct dex_code_item {
    dex_ushort registers_size;
    dex_ushort ins_size;
    dex_ushort outs_size;
    dex_ushort tries_size;
    dex_uint debug_info_off;
    debug_info_item debug_info;
    dex_uint insns_size;
    std::vector<dex_ushort> insns;
    dex_ushort padding;
    std::vector<try_item> tries;
    encoded_catch_handler_list handlers;
} code_item;

typedef struct dex_encoded_method {
    dex_uint method_idx_diff;
    dex_uint access_flags;
    dex_uint code_off;
    code_item code;
} encoded_method;

typedef struct dex_class_data_item {
    dex_uint static_fields_size;
    dex_uint instance_fields_size;
    dex_uint direct_methods_size;
    dex_uint virtual_methods_size;
    std::vector<encoded_field> static_fields;
    std::vector<encoded_field> instance_fields;
    std::vector<encoded_method> direct_methods;
    std::vector<encoded_method> virtual_methods;
} class_data_item;

typedef struct dex_annotations_directory_item {
    dex_uint class_annotations_off;
    dex_uint fields_size;
    dex_uint annotated_methods_size;
    dex_uint annotated_parameters_size;
    annotation_set_item class_annotation;
    std::vector<field_annotation> field_annotations;
    std::vector<method_annotation> method_annotations;
    std::vector<parameter_annotation> parameter_annotations;
} annotations_directory_item;

typedef enum dex_parse_error {
    DEX_PARSER_SUCCESS = 0
} parse_error;

class DexFile {

public:
    parse_error parseFromBuffer(std::string *buffer);
    std::u16string &getTypeName(dex_uint idx);
    std::u16string &getClassName(dex_uint class_idx);
    std::u16string &getString(dex_uint idx);
protected:
    template <class T>
    bool read(T *data);
    bool read(void * data, size_t size);
    bool readByte(dex_byte *data);
    bool readUbyte(dex_ubyte *data);
    bool readShort(dex_short *data);
    bool readUshort(dex_ushort *data);
    bool readInt(dex_int *data);
    bool readUint(dex_uint *data);
    bool readLong(dex_long *data);
    bool readUlong(dex_ulong *data);
    bool readSleb128(dex_int *data);
    bool readUleb128(dex_uint *data);
    bool readUleb128p1(dex_uint *data);
    bool readEncodedValue(encoded_value *data);
    bool readEncodedValueArray(encoded_array *data);
    bool readEncodedAnnotation(encoded_annotation *data);
    bool readAnnotationElement(annotation_element *data);
    bool readAnnotationSetItem(annotation_set_item *data);
    bool readAnnotation(annotations_directory_item *data);
    bool readAnnotationSetRefList(annotation_set_ref_list *data);
    bool readDebugInfoItem(debug_info_item *data);
    bool readEncodedTypeAddrPair(encoded_type_addr_pair *data);
    bool readEncodedCatchHandler(encoded_catch_handler *data);
    bool readEncodedCatchHandlerList(encoded_catch_handler_list *data);
    bool readTryItem(try_item *data);
    bool readEncodeField(encoded_field *data);
    bool readEncodeMethod(encoded_method *data);
    bool readClassDataItem(class_data_item *data);
    bool readCodeItem(code_item *data);
    bool parseTypeList(type_list *data);
    bool parseHeadItem();
    bool parseMapList();
    bool parseStringData();
    bool parseType();
    bool parsePrototype();
    bool parseField();
    bool parseMethod();
    bool parseClass();

private:
    dex_ulong seekPosition;
    std::string *dexFileBuffer;

public:
    std::shared_ptr<header_item> pDexHeaderItem;
    std::shared_ptr<std::vector<map_item>> pMapList;
    std::shared_ptr<std::vector<std::u16string>> pStringDataList;
    std::shared_ptr<std::vector<type_id_item>> pTypeIdItemList;
    std::shared_ptr<std::vector<proto_id_item>> pProtoIdItemList;
    std::shared_ptr<std::vector<method_id_item>> pMethodIdItemList;
    std::shared_ptr<std::vector<field_id_item>> pFieldIdItemList;
    std::shared_ptr<std::vector<class_def_item>> pClassDefItemList;
};


#endif //ART_LEARNING_DEXFILE_H
