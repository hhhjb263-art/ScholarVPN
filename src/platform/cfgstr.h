#pragma once

#include <cstdint>
#include <string>

#if defined(_WIN32)
using cfgstr = std::wstring;
#define CS(s) L##s
#else
using cfgstr = std::string;
#define CS(s) s
#endif

std::string cfg_to_utf8(const cfgstr& s);
cfgstr     cfg_from_utf8(const std::string& s);

cfgstr cfg_num(long long value);

cfgstr cfg_path_join(const cfgstr& dir, const cfgstr& name);

bool cfg_unlink(const cfgstr& path);

bool cfg_restrict_file(const cfgstr& path);

cfgstr cfg_app_dir();

cfgstr cfg_config_root();
