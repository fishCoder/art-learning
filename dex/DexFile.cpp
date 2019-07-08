//
// Created by fulongbin on 2019-06-28.
//
#include <boost/endian/conversion.hpp>
#include <boost/endian/buffers.hpp>
#include "DexFile.h"


/**
 * 从string中解析Dex文件
 * @param buffer
 * @return
 */
parse_error DexFile::parseFromBuffer(std::string *buffer) {
    this->seekPosition = 0;
    this->dexFileBuffer = buffer;

    this->parseHeadItem();
    this->parseMapList();
    this->parseStringData();
    this->parseType();
    this->parsePrototype();
    this->parseField();
    this->parseMethod();
    this->parseClass();
    return DEX_PARSER_SUCCESS;
}

template <class T>
bool DexFile::read(T *data) {
    int size = sizeof(T);
    bool result = read(data, size);
    if (result) {
        //大小端转换
        boost::endian::little_to_native_inplace(*data);
    }
    return result;
}


bool DexFile::read(void *data, size_t size) {
    const char *buffer = this->dexFileBuffer->c_str();
    if (this->seekPosition + size > this->dexFileBuffer->length()) {
        log_error << "读取数据出错 buffer length " << this->dexFileBuffer->length() << " 读取目标 " << this->seekPosition + size;
        return false;
    }
    std::memcpy(data,buffer + this->seekPosition, size);
    this->seekPosition += size;
//    log_info << "read size:" << size;
//    log_info << "seekPosition:" << this->seekPosition;
    return true;
}

bool DexFile::readByte(dex_byte *data) {
    return read(data);
}

bool DexFile::readUbyte(dex_ubyte *data) {
    return read(data);
}

bool DexFile::readShort(dex_short *data) {
    return read(data);
}

bool DexFile::readUshort(dex_ushort *data) {
    return read(data);
}

bool DexFile::readInt(dex_int *data) {
    return read(data);
}

bool DexFile::readUint(dex_int *data) {
    return read(data);
}

bool DexFile::readLong(dex_long *data) {
    return read(data);
}

bool DexFile::readUlong(dex_ulong *data) {
    return read(data);
}

bool DexFile::readSleb128(dex_int *data) {
    dex_byte *ptr = (dex_byte *) (this->dexFileBuffer->c_str() + this->seekPosition);
    dex_int result = *(ptr++);

    if (result <= 0x7f) {
        result = (result << 25) >> 25;
    } else {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur <= 0x7f) {
            result = (result << 18) >> 18;
        } else {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur <= 0x7f) {
                result = (result << 11) >> 11;
            } else {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur <= 0x7f) {
                    result = (result << 4) >> 4;
                } else {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *data = result;
    this->seekPosition = (dex_ulong)ptr - (dex_ulong)dexFileBuffer->c_str();
    return true;
}

bool DexFile::readUleb128(dex_uint *data) {
    dex_ubyte *ptr = (dex_ubyte *) (this->dexFileBuffer->c_str() + this->seekPosition);
    dex_uint result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *data = result;
    this->seekPosition = (dex_ulong)ptr - (dex_ulong)dexFileBuffer->c_str();
    return true;
}

bool DexFile::readUleb128p1(dex_uint *data) {
    *data = this->readUleb128(data) + 1;
    return true;
}

bool DexFile::readEncodedValue(encoded_value *data) {
    dex_ubyte arg_and_type;
    read(&arg_and_type);
    data->value_arg  = arg_and_type >> 5;
    data->value_type = arg_and_type & 0b00011111;
   switch (data->value_type) {
        case VALUE_BYTE:
        case VALUE_SHORT:
        case VALUE_CHAR:
        case VALUE_INT:
        case VALUE_LONG:
        case VALUE_FLOAT:
        case VALUE_DOUBLE:
        case VALUE_METHOD_TYPE:
        case VALUE_METHOD_HANDLE:
        case VALUE_STRING:
        case VALUE_TYPE:
        case VALUE_FIELD:
        case VALUE_METHOD:
        case VALUE_ENUM:
            data->value.reserve(data->value_arg+1);
            read(&data->value[0], data->value_arg+1);
            break;
        case VALUE_ARRAY:{
            encoded_array *encodedArray = new encoded_array;
            data->encoded_array.reset(encodedArray);
            readEncodedValueArray(encodedArray);
        }
            break;
        case VALUE_ANNOTATION:{
            encoded_annotation *encodedAnnotation = new encoded_annotation;
            data->encoded_annotation.reset(encodedAnnotation);
            readEncodedAnnotation(encodedAnnotation);
        }
            break;
    }
    return true;
}

bool DexFile::readAnnotationElement(annotation_element *data) {
    readUleb128(&data->name_idx);
    readEncodedValue(&data->value);
    return true;
}

bool DexFile::readEncodedAnnotation(encoded_annotation *data) {
    readUleb128(&data->type_idx);
    readUleb128(&data->size);
    data->elements.resize(data->size);
    for (int i = 0; i < data->size; ++i) {
        annotation_element element;
        readAnnotationElement(&element);
        data->elements[i] = std::move(element);
    }
    return true;
}

bool DexFile::readEncodedValueArray(encoded_array *data) {
    readUleb128(&data->size);
    data->values.resize(data->size);
    for (int i = 0; i < data->size; ++i) {
        encoded_value value;
        readEncodedValue(&value);
        data->values[i] = std::move(value);
    }
    return true;
}

bool DexFile::parseHeadItem() {
    header_item *ptrHeaderItem = new header_item;
    read(ptrHeaderItem->magic, sizeof(ptrHeaderItem->magic));
    read(&ptrHeaderItem->checksum);
    read(ptrHeaderItem->signature, sizeof(ptrHeaderItem->signature));
    read(&ptrHeaderItem->file_size);
    read(&ptrHeaderItem->header_size);
    read(&ptrHeaderItem->endian_tag);
    read(&ptrHeaderItem->link_size);
    read(&ptrHeaderItem->link_off);
    read(&ptrHeaderItem->map_off);
    read(&ptrHeaderItem->string_ids_size);
    read(&ptrHeaderItem->string_ids_off);
    read(&ptrHeaderItem->type_ids_size);
    read(&ptrHeaderItem->type_ids_off);
    read(&ptrHeaderItem->proto_ids_size);
    read(&ptrHeaderItem->proto_ids_off);
    read(&ptrHeaderItem->field_ids_size);
    read(&ptrHeaderItem->field_ids_off);
    read(&ptrHeaderItem->method_ids_size);
    read(&ptrHeaderItem->method_ids_off);
    read(&ptrHeaderItem->class_defs_size);
    read(&ptrHeaderItem->class_defs_off);
    read(&ptrHeaderItem->data_size);
    read(&ptrHeaderItem->data_off);


    pDexHeaderItem.reset(ptrHeaderItem);
    return true;
}

bool DexFile::parseMapList() {
    this->seekPosition = pDexHeaderItem->map_off;
    dex_uint mapListSize;
    read(&mapListSize);
    pMapList.reset(new std::vector<map_item>());
    pMapList->resize(mapListSize);

    for (int i = 0; i < mapListSize; ++i) {
        map_item mapItem;
        read(&mapItem.type);
        read(&mapItem.unused);
        read(&mapItem.size);
        read(&mapItem.offset);
        (*pMapList)[i] = std::move(mapItem);
    }

    return true;
}

bool DexFile::parseStringData() {
    this->seekPosition = pDexHeaderItem->string_ids_off;
    dex_uint stringDataSize = pDexHeaderItem->string_ids_size;
    pStringDataList.reset(new std::vector<std::u16string>());
    pStringDataList->reserve(stringDataSize);

    /**
     * 获取字符串数据偏移量
     */
    std::vector<string_id_item> stringIdList;
    stringIdList.resize(stringDataSize);
    for (int i = 0; i < stringDataSize; ++i) {
        string_id_item stringIdItem;
        read(&stringIdItem.string_data_off);
        stringIdList[i] = std::move(stringIdItem);
    }

    std::string buffer = *dexFileBuffer;

    for (int j = 0; j < stringDataSize; ++j) {
        string_id_item &item = stringIdList[j];
        string_data_item stringDataItem;
        this->seekPosition = item.string_data_off;
        readUleb128(&stringDataItem.utf16_size);
        dex_uint offset = this->seekPosition;
        std::u16string data;
        data.resize(stringDataItem.utf16_size);
        for (int i = 0; i < stringDataItem.utf16_size; ++i) {
            dex_ushort utf16char;
            dex_ubyte ch = buffer[offset++] & 0xff;
            if (ch == 0) {
                break;
            }
            if (ch < 0x80) {
                utf16char = ch;
            } else if ((ch & 0xe0) == 0xc0) {
                dex_ushort a = ch;
                dex_ushort b = buffer[offset++] & 0xff;
                if ((b & 0xC0) != 0x80) {
                    log_error << "bad second byte";
                    return false;
                }
                utf16char = ((a & 0x1F) << 6) | (b & 0x3F);
            } else if ((ch & 0xf0) == 0xe0) {
                dex_ushort a = ch;
                dex_ushort b = buffer[offset++] & 0xff;
                dex_ushort c = buffer[offset++] & 0xff;
                if (((b & 0xC0) != 0x80) || ((c & 0xC0) != 0x80)) {
                    log_error << "bad second or third byte";
                    return false;
                }
                utf16char = ((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F);
            } else {
                log_error << "bad byte";
                return false;
            }
            data[i] = utf16char;
        }
        (*pStringDataList)[j] = std::move(data);
    }

    return true;
}

bool DexFile::parseType() {
    seekPosition = pDexHeaderItem->type_ids_off;
    dex_uint typeListSize = pDexHeaderItem->type_ids_size;
    pTypeIdItemList.reset(new std::vector<type_id_item>);
    pTypeIdItemList->resize(typeListSize);
    for (int i = 0; i < typeListSize; ++i) {
        type_id_item typeIdItem;
        read(&typeIdItem.descriptor_idx);
        (*pTypeIdItemList)[i] = std::move(typeIdItem);
    }
    return true;
}

bool DexFile::parseTypeList(type_list *typeList) {
    read(&typeList->size);
    typeList->list.resize(typeList->size);
    for (int i = 0; i < typeList->size; ++i) {
        type_item typeItem;
        read(&typeItem.type_idx);
        typeList->list[i] = std::move(typeItem);
    }
    return true;
}

bool DexFile::parsePrototype() {
    seekPosition = pDexHeaderItem->proto_ids_off;
    dex_uint protoListSize = pDexHeaderItem->proto_ids_size;
    pProtoIdItemList.reset(new std::vector<proto_id_item>());
    pProtoIdItemList->resize(protoListSize);
    std::vector<proto_id_item> & protoIdItemList = *pProtoIdItemList;
    for (int i = 0; i < protoListSize; ++i) {
        proto_id_item protoIdItem;
        read(&protoIdItem.shorty_idx);
        read(&protoIdItem.return_type_idx);
        read(&protoIdItem.parameters_off);
        protoIdItemList[i] = std::move(protoIdItem);
    }

    for (int j = 0; j < protoListSize; ++j) {
        proto_id_item & item = protoIdItemList[j];
        if (protoIdItemList[j].parameters_off > 0) {
            this->seekPosition = protoIdItemList[j].parameters_off;
            type_list typeList;
            parseTypeList(&typeList);
            protoIdItemList[j].parameters_list = std::move(typeList);
        }
    }
    return true;
}

bool DexFile::parseField() {
    dex_uint fieldSize = pDexHeaderItem->field_ids_size;
    seekPosition = pDexHeaderItem->field_ids_off;

    pFieldIdItemList.reset(new std::vector<field_id_item>());
    pFieldIdItemList->resize(fieldSize);

    for (int i = 0; i < fieldSize; ++i) {
        field_id_item fieldIdItem;
        read(&fieldIdItem.class_idx);
        read(&fieldIdItem.type_idx);
        read(&fieldIdItem.name_idx);
        (*pFieldIdItemList)[i] = std::move(fieldIdItem);
    }
    return true;
}

bool DexFile::parseMethod() {
    dex_uint methodSize = pDexHeaderItem->method_ids_size;
    seekPosition = pDexHeaderItem->method_ids_off;

    pMethodIdItemList.reset(new std::vector<method_id_item>());
    pMethodIdItemList->resize(methodSize);
    for (int i = 0; i < methodSize; ++i) {
        method_id_item methodIdItem;
        read(&methodIdItem.class_idx);
        read(&methodIdItem.proto_idx);
        read(&methodIdItem.name_idx);

        (*pMethodIdItemList)[i] = std::move(methodIdItem);
    }

    return true;
}

bool DexFile::parseClass() {
    dex_uint  classSize = pDexHeaderItem->class_defs_size;
    seekPosition = pDexHeaderItem->class_defs_off;

    pClassDefItemList.reset(new std::vector<class_def_item>());
    pClassDefItemList->resize(classSize);

    for (int i = 0; i < classSize; ++i) {
        class_def_item classDefItem;
        read(&classDefItem.class_idx);
        read(&classDefItem.access_flags);
        read(&classDefItem.superclass_idx);
        read(&classDefItem.interfaces_off);
        read(&classDefItem.source_file_idx);
        read(&classDefItem.annotations_off);
        read(&classDefItem.class_data_off);
        read(&classDefItem.static_values_off);

        (*pClassDefItemList)[i] = std::move(classDefItem);
    }

    for (int j = 0; j < classSize; ++j) {
        class_def_item &item = (*pClassDefItemList)[j];

        if (item.class_data_off > 0) {
            seekPosition = item.class_data_off;
            item.class_data.reset(new class_data_item);
            readClassDataItem(item.class_data.get());
        }

        if (item.interfaces_off > 0) {
            seekPosition = item.interfaces_off;
            type_list typeList;
            parseTypeList(&typeList);
            item.interfaces_list = std::move(typeList);
        }
        if (item.annotations_off > 0) {
            seekPosition = item.annotations_off;
            annotations_directory_item annotationsDirectoryItem;
            readAnnotation(&annotationsDirectoryItem);
        }
    }

    return true;
}

bool DexFile::readAnnotation(annotations_directory_item *annotationsDirectoryItem) {

    read(&annotationsDirectoryItem->class_annotations_off);
    read(&annotationsDirectoryItem->fields_size);
    read(&annotationsDirectoryItem->annotated_methods_size);
    read(&annotationsDirectoryItem->annotated_parameters_size);

    annotationsDirectoryItem->field_annotations.resize(annotationsDirectoryItem->fields_size);
    for (int i = 0; i < annotationsDirectoryItem->fields_size; ++i) {
        field_annotation fieldAnnotation;
        read(&fieldAnnotation.field_idx);
        read(&fieldAnnotation.annotations_off);
        annotationsDirectoryItem->field_annotations[i] = std::move(fieldAnnotation);
    }

    annotationsDirectoryItem->method_annotations.resize(annotationsDirectoryItem->annotated_methods_size);
    for (int j = 0; j < annotationsDirectoryItem->annotated_methods_size; ++j) {
        method_annotation methodAnnotation;
        read(&methodAnnotation.method_idx);
        read(&methodAnnotation.annotations_off);
        annotationsDirectoryItem->method_annotations[j] = std::move(methodAnnotation);
    }

    annotationsDirectoryItem->parameter_annotations.resize(annotationsDirectoryItem->annotated_parameters_size);
    for (int k = 0; k < annotationsDirectoryItem->annotated_parameters_size; ++k) {
        parameter_annotation parameterAnnotation;
        read(&parameterAnnotation.method_idx);
        read(&parameterAnnotation.annotations_off);
        annotationsDirectoryItem->parameter_annotations[k] = std::move(parameterAnnotation);
    }

    if (annotationsDirectoryItem->class_annotations_off > 0) {
        seekPosition = annotationsDirectoryItem->class_annotations_off;
        readAnnotationSetItem(&annotationsDirectoryItem->class_annotation);
    }

    for (int i = 0; i < annotationsDirectoryItem->fields_size; ++i) {
        field_annotation &annotation = annotationsDirectoryItem->field_annotations[i];
        seekPosition = annotation.annotations_off;
        annotation_set_item annotationSetItem;
        readAnnotationSetItem(&annotationSetItem);
        annotation.field_annotation = std::move(annotationSetItem);
    }

    for (int l = 0; l < annotationsDirectoryItem->annotated_methods_size; ++l) {
        method_annotation &methodAnnotation = annotationsDirectoryItem->method_annotations[l];
        seekPosition = methodAnnotation.annotations_off;
        annotation_set_item annotationSetItem;
        readAnnotationSetItem(&annotationSetItem);
        methodAnnotation.method_annotations = std::move(annotationSetItem);
    }

    for (int m = 0; m < annotationsDirectoryItem->annotated_parameters_size; ++m) {
        parameter_annotation &parameterAnnotation = annotationsDirectoryItem->parameter_annotations[m];
        seekPosition = parameterAnnotation.annotations_off;
        annotation_set_ref_list  annotationSetRefList;
        readAnnotationSetRefList(&annotationSetRefList);
        parameterAnnotation.parameter_annotations = std::move(annotationSetRefList);
    }
    return true;
}

bool DexFile::readAnnotationSetRefList(annotation_set_ref_list *data) {
    read(&data->size);
    data->list.resize(data->size);
    for (int i = 0; i < data->size; ++i) {
        annotation_set_ref_item item;
        read(&item.annotations_off);
        data->list[i] = std::move(item);
    }
    for (int i = 0; i < data->size; ++i) {
        annotation_set_ref_item &item = data->list[i];
        seekPosition = item.annotations_off;
        readAnnotationSetItem(&item.item);
    }
    return true;
}

bool DexFile::readAnnotationSetItem(annotation_set_item *annotationSetItem) {
    read(&annotationSetItem->size);
    annotationSetItem->entries.resize(annotationSetItem->size);

    for (int i = 0; i < annotationSetItem->size; ++i) {
        annotation_off_item offItem;
        read(&offItem.annotation_off);
        annotationSetItem->entries[i] = std::move(offItem);
    }
    for (int i = 0; i < annotationSetItem->size; ++i) {
        annotation_off_item &offItem = annotationSetItem->entries[i];
        seekPosition = offItem.annotation_off;
        read(&offItem.annotation.visibility);
        readEncodedAnnotation(&offItem.annotation.annotation);
    }
    return true;
}

bool DexFile::readDebugInfoItem(debug_info_item *data) {
    readUleb128(&data->line_start);
    readUleb128(&data->parameters_size);
    data->parameter_names.resize(data->parameters_size);
    for (int i = 0; i < data->parameters_size; ++i) {
        readUleb128p1(&data->parameter_names[i]);
    }
    return true;
}

bool DexFile::readEncodedTypeAddrPair(encoded_type_addr_pair *data) {
    readUleb128(&data->type_idx);
    readUleb128(&data->addr);
    log_info << getTypeName(data->type_idx);
    return true;
}

bool DexFile::readEncodedCatchHandler(encoded_catch_handler *data) {
    readSleb128(&data->size);
    dex_uint size = std::abs(data->size);
    data->handlers.resize(size);
    for (int i = 0; i < size; ++i) {
        readEncodedTypeAddrPair(&data->handlers[i]);
    }
    if (data->size <= 0) {
        readUleb128(&data->catch_all_addr);
    }
    return true;
}

bool DexFile::readEncodedCatchHandlerList(encoded_catch_handler_list *data) {
    readUleb128(&data->size);
    data->list.resize(data->size);
    for (int i = 0; i < data->size; ++i) {
        readEncodedCatchHandler(&data->list[i]);
    }
    return true;
}

bool DexFile::readTryItem(try_item *data) {
    read(&data->start_addr);
    read(&data->insn_count);
    read(&data->handler_off);
    return true;
}

bool DexFile::readClassDataItem(class_data_item *data) {
    readUleb128(&data->static_fields_size);
    readUleb128(&data->instance_fields_size);
    readUleb128(&data->direct_methods_size);
    readUleb128(&data->virtual_methods_size);

    data->static_fields.resize(data->static_fields_size);
    for (int i = 0; i < data->static_fields_size; ++i) {
        readEncodeField(&data->static_fields[i]);
    }

    data->instance_fields.resize(data->instance_fields_size);
    for (int j = 0; j < data->instance_fields_size; ++j) {
        readEncodeField(&data->instance_fields[j]);
    }

    data->direct_methods.resize(data->direct_methods_size);
    for (int k = 0; k < data->direct_methods_size; k+=1) {
        readEncodeMethod(&data->direct_methods[k]);
    }

    data->virtual_methods.resize(data->virtual_methods_size);
    for (int m = 0; m < data->virtual_methods_size; ++m) {
        readEncodeMethod(&data->virtual_methods[m]);
    }
    return true;
}

bool DexFile::readEncodeField(encoded_field *data) {
    readUleb128(&data->field_idx_diff);
    readUleb128(&data->access_flags);
    return true;
}

bool DexFile::readEncodeMethod(encoded_method *data) {
    readUleb128(&data->method_idx_diff);
    readUleb128(&data->access_flags);
    readUleb128(&data->code_off);
    if (data->code_off > 0) {
        dex_uint originPosition = seekPosition;
        seekPosition = data->code_off;
        readCodeItem(&data->code);
        seekPosition = originPosition;
    }

    return true;
}

bool DexFile::readCodeItem(code_item *data) {
    read(&data->registers_size);
    read(&data->ins_size);
    read(&data->outs_size);
    read(&data->tries_size);
    read(&data->debug_info_off);
    dex_uint seek = seekPosition;
    seekPosition = data->debug_info_off;
    readDebugInfoItem(&data->debug_info);
    seekPosition = seek;
    read(&data->insns_size);
    data->insns.resize(data->insns_size);
    for (int i = 0; i < data->insns_size; ++i) {
        read(&data->insns[i]);
    }
    if (data->tries_size!=0 && data->insns_size%2==1){
        read(&data->padding);
    }
    data->tries.resize(data->tries_size);
    for (int j = 0; j < data->tries_size; ++j) {
        readTryItem(&data->tries[j]);
    }
    if (data->tries_size > 0) {
        readEncodedCatchHandlerList(&data->handlers);
    }
    return true;
}

std::u16string& DexFile::getClassName(dex_uint class_idx) {
    return getString((*pTypeIdItemList)[class_idx].descriptor_idx);
}

std::u16string& DexFile::getTypeName(dex_uint idx) {
    type_id_item &item = (*pTypeIdItemList)[idx];
    return getString(item.descriptor_idx);
}

std::u16string& DexFile::getString(dex_uint idx) {
    return (*pStringDataList)[idx];
}