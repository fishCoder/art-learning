//
// Created by fulongbin on 2019-06-28.
//

#include "base.h"
#include <iostream>
#include <fstream>

bool base::ReadFileToString(std::string filename, std::string &content) {
    std::ifstream fileSteam(filename, std::ios::in | std::ios::binary | std::ios::ate);
    if (!fileSteam.is_open()) {
        log_error  <<  "open " <<  filename << " fail !" ;
        return false;
    } else {
        content.clear();
        auto size = fileSteam.tellg();
        content.resize(size);
        fileSteam.seekg(0);
        if(fileSteam.read(&content[0], size)) {
            return true;
        } else {
            return false;
        }
    }
}