//
// Created by fulongbin on 2019-06-28.
//
#include <string>
#include <iomanip>
#include "../base/base.h"
#include "../dex/DexFile.h"

void print(std::shared_ptr<header_item> pDexHeadItem) {
    log_info << std::setw(20) << " magic \t" << pDexHeadItem->magic;
    log_info << std::setw(20) << " checksum \t" << pDexHeadItem->checksum;
    log_info << std::setw(20) << " signature \t" << pDexHeadItem->signature;
    log_info << std::setw(20) << " file_size \t" << pDexHeadItem->file_size;
    log_info << std::setw(20) << " header_size \t" << pDexHeadItem->header_size;
    log_info << std::setw(20) << " endian_tag \t" << pDexHeadItem->endian_tag;
    log_info << std::setw(20) << " link_size \t" << pDexHeadItem->link_size;
    log_info << std::setw(20) << " link_off \t" << pDexHeadItem->link_off;
    log_info << std::setw(20) << " map_off \t" << pDexHeadItem->map_off;
    log_info << std::setw(20) << " string_ids_size \t" << pDexHeadItem->string_ids_size;
    log_info << std::setw(20) << " string_ids_off \t" << pDexHeadItem->string_ids_off;
    log_info << std::setw(20) << " type_ids_size \t" << pDexHeadItem->type_ids_size;
    log_info << std::setw(20) << " type_ids_off \t" << pDexHeadItem->type_ids_off;
    log_info << std::setw(20) << " proto_ids_size \t" << pDexHeadItem->proto_ids_size;
    log_info << std::setw(20) << " proto_ids_off \t" << pDexHeadItem->proto_ids_off;
    log_info << std::setw(20) << " field_ids_size \t" << pDexHeadItem->field_ids_size;
    log_info << std::setw(20) << " field_ids_off \t" << pDexHeadItem->field_ids_off;
    log_info << std::setw(20) << " method_ids_size \t" << pDexHeadItem->method_ids_size;
    log_info << std::setw(20) << " class_defs_size \t" << pDexHeadItem->class_defs_size;
    log_info << std::setw(20) << " class_defs_off \t" << pDexHeadItem->class_defs_off;
    log_info << std::setw(20) << " data_size \t" << pDexHeadItem->data_size;
    log_info << std::setw(20) << " data_off \t" << pDexHeadItem->data_off;
}

void print(std::shared_ptr<std::vector<map_item>> pMapList) {
    std::vector<map_item> &mapList = *pMapList;
    for (int i = 0; i < mapList.size(); ++i) {
        map_item &item = mapList[i];
        log_info << "map list " << i << " type 0x" << std::hex << item.type << " size " << std::dec << item.size << " offset " << item.offset;
    }
}

void print(std::shared_ptr<std::vector<std::u16string>> pStringDataList) {
    std::vector<std::u16string> &stringDataList = *pStringDataList;
    for (int i = 0; i < stringDataList.size(); ++i) {
        log_info << "string[ " << std::setw(5) << i << "] \"" << stringDataList[i] << "\"";
    }
}

void printType(DexFile &dexFile) {
    std::vector<type_id_item> &typeIdItemList = *dexFile.pTypeIdItemList;

    for (int i = 0; i < typeIdItemList.size(); ++i) {
        type_id_item &item = typeIdItemList[i];
        log_info << "type[ " << std::setw(4) << i << "] " << dexFile.getString(item.descriptor_idx) << "";
    }
}

void printPrototype(DexFile &dexFile) {
    std::vector<proto_id_item> &protoIdItemList = *dexFile.pProtoIdItemList;
    std::vector<type_id_item> &typeIdItemList = *dexFile.pTypeIdItemList;
    for (int i = 0; i < protoIdItemList.size(); ++i) {
        proto_id_item &item = protoIdItemList[i];
        log_info << "Prototype[ " << std::setw(4) << i << "] " << dexFile.getString(item.shorty_idx) << " return " << dexFile.getTypeName(item.return_type_idx);
        if (item.parameters_off > 0) {
            std::u16string params;
            for (int j = 0; j < item.parameters_list.size; ++j) {
                type_id_item &typeIdItem = typeIdItemList[item.parameters_list.list[j].type_idx];
                params += dexFile.getString(typeIdItem.descriptor_idx);
            }
            log_info << "Prototype[ " << std::setw(4) << i << "] parameters_list " << params;
        }
    }
}

void printField(DexFile &dexFile) {
    std::vector<field_id_item> & fieldIdItemList = *dexFile.pFieldIdItemList;
    for (int i = 0; i < fieldIdItemList.size(); ++i) {
        field_id_item & item = fieldIdItemList[i];
        log_info << "Prototype[ " << std::setw(4) << i << "] " << dexFile.getClassName(item.class_idx)
        << "  " << dexFile.getTypeName(item.type_idx)
        << "  " << dexFile.getString(item.name_idx) ;
    }
}

void printMethod(DexFile &dexFile) {
    std::vector<method_id_item> &methodIdItemList = *dexFile.pMethodIdItemList;
    std::vector<proto_id_item> &protoIdItemList = *dexFile.pProtoIdItemList;
    for (int i = 0; i < methodIdItemList.size(); ++i) {
        method_id_item & item = methodIdItemList[i];
        proto_id_item &protoIdItem = protoIdItemList[item.proto_idx];
        log_info << "Method[ " << std::setw(4) << i << "] " << dexFile.getClassName(item.class_idx)
                 << "  " << dexFile.getString(protoIdItem.shorty_idx)
                 << "  " << dexFile.getString(item.name_idx) ;
    }
}


void printClass(DexFile &dexFile) {
    std::vector<class_def_item> &classDefItemList = *dexFile.pClassDefItemList;
    for (int i = 0; i < classDefItemList.size(); ++i) {
        class_def_item &item = classDefItemList[i];
        log_info << "Class[ " << std::setw(4) << i << "] " << dexFile.getClassName(item.class_idx)
        << " extends " << ((item.superclass_idx == NO_INDEX) ? u"null" : dexFile.getClassName(item.class_idx));
        if (item.source_file_idx != NO_INDEX) {
            log_info << "source file : " << dexFile.getString(item.source_file_idx);
        }
        if (item.interfaces_off > 0) {
            log_info << "interfaces :";
            for (int j = 0; j < item.interfaces_list.size; ++j) {
                type_item &typeItem = item.interfaces_list.list[j];
                log_info << dexFile.getTypeName(typeItem.type_idx);
            }
        }
        if (item.class_data_off > 0) {
            log_info << "filed:";
            dex_uint idx = 0;
            for (int index = 0; index < item.class_data->static_fields_size; ++index) {
                encoded_field &field = item.class_data->static_fields[index];
                idx += field.field_idx_diff;
                field_id_item &fieldIdItem = (*dexFile.pFieldIdItemList)[idx];
                log_info << "static " << dexFile.getTypeName(fieldIdItem.type_idx) << " " << dexFile.getString(fieldIdItem.name_idx);
            }
            idx = 0;
            for (int index = 0; index < item.class_data->instance_fields_size; ++index) {
                encoded_field &field = item.class_data->instance_fields[index];
                idx += field.field_idx_diff;
                field_id_item &fieldIdItem = (*dexFile.pFieldIdItemList)[idx];
                log_info << "instance " << dexFile.getTypeName(fieldIdItem.type_idx) << " " << dexFile.getString(fieldIdItem.name_idx);
            }
            idx = 0;
            for (int index = 0; index < item.class_data->direct_methods_size; ++index) {
                encoded_method &method = item.class_data->direct_methods[index];
                idx += method.method_idx_diff;
                method_id_item &methodIdItem = dexFile.pMethodIdItemList->at(idx);
                log_info << "direct method " << dexFile.getString(methodIdItem.name_idx);
                log_info << "registers_size " << method.code.registers_size;
                log_info << "tries_size " << method.code.tries_size;
                log_info << "code size " << method.code.insns_size;
                if (method.code.handlers.size>0){
                    log_info << "catch";
                    for (int j = 0; j < method.code.handlers.size; ++j) {
                        encoded_catch_handler &encodedCatchHandler = method.code.handlers.list[j];
                        for (int k = 0; k < encodedCatchHandler.size; ++k) {
                            encoded_type_addr_pair &pair = encodedCatchHandler.handlers[k];
                            log_info << "\t" << dexFile.getTypeName(pair.type_idx);
                        }
                    }
                }
            }
            idx = 0;
            for (int index = 0; index < item.class_data->virtual_methods_size; ++index) {
                encoded_method &method = item.class_data->virtual_methods[index];
                idx += method.method_idx_diff;
                method_id_item &methodIdItem = dexFile.pMethodIdItemList->at(idx);
                log_info << "virtual method " << dexFile.getString(methodIdItem.name_idx);
                log_info << "registers_size " << method.code.registers_size;
                log_info << "code size " << method.code.insns_size;
                if (method.code.handlers.size>0){
                    log_info << "catch";
                    for (int j = 0; j < method.code.handlers.size; ++j) {
                        encoded_catch_handler &encodedCatchHandler = method.code.handlers.list[j];
                        for (int k = 0; k < encodedCatchHandler.size; ++k) {
                            encoded_type_addr_pair &pair = encodedCatchHandler.handlers[k];
                            log_info << "\t" << dexFile.getTypeName(pair.type_idx);
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    if (argc > 1) {
        log_error << "请输入dex文件";
    }
    std::string filename(argv[1]);
    log_info << "dex文件路径 " << filename;
    std::string content;
    base::ReadFileToString(filename, content);
    DexFile dexFile;
    dexFile.parseFromBuffer(&content);
    print(dexFile.pDexHeaderItem);
    print(dexFile.pMapList);
    print(dexFile.pStringDataList);
    printType(dexFile);
    printPrototype(dexFile);
    printField(dexFile);
    printMethod(dexFile);
    printClass(dexFile);
}