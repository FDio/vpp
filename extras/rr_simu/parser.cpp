/* Copyright (c) 2023 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include "parser.hpp"
#include <iostream>

std::unordered_map<std::string, std::string>
Parser::readConfigFile (std::string fileName)
{

  std::string config, temp;
  std::ifstream fileStream (fileName);
  if (fileStream.is_open ())
    {
      while (getline (fileStream, temp))
	config += "\n" + temp;
    }
  fileStream.close ();
  return parseConfigFile (config);
}

std::unordered_map<std::string, std::string>
Parser::parseConfigFile (std::string configInfo)
{

  std::stringstream cfgFile (configInfo);
  std::string line;
  std::unordered_map<std::string, std::string> config = {};

  while (std::getline (cfgFile, line))
    {
      std::istringstream is_line (line);
      std::string key;
      if (std::getline (is_line, key, '='))
	{
	  std::string value;
	  if (std::getline (is_line, value))
	    config.emplace (key, value);
	}
    }

  return config;
}

std::map<int, float>
Parser::parsePairArray (std::string string)
{

  std::stringstream stream_array (string);
  std::string s_pair;
  std::map<int, float> pair_array_map = {};

  while (std::getline (stream_array, s_pair, '|') && s_pair != "0")
    {
      std::stringstream stream_pair (s_pair);
      std::string s_class, s_value;
      std::getline (stream_pair, s_class, ',');
      std::getline (stream_pair, s_value, ',');
      pair_array_map.emplace (stod (s_class), stod (s_value));
    }
  return pair_array_map;
}