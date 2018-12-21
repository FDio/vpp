/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Intel, Travelping and/or its affiliates.
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
 * limitations under the License.
 *------------------------------------------------------------------
 */

/*
#*************************************************************
#  Copyright (c) 2003-2017, Emerging Threats
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#  following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#*************************************************************
*/

#ifndef dpi_app_match_h
#define dpi_app_match_h

typedef enum
{
  DPI_APP_CISCO = 1,
  DPI_APP_GOOGLE = 2,
  DPI_APP_BING = 3,
  DPI_APP_MSN = 4,
  DPI_APP_YAHOO = 5,
  DPI_APP_YAHOOMAIL = 6,
  DPI_APP_INTEL = 7,
  DPI_APP_AMAZON = 8,
  DPI_APP_AMD = 9,
  DPI_APP_BAIDU = 10,
  DPI_APP_APPLE = 11,
  DPI_APP_FACEBOOK = 12,
  DPI_APP_EBAY = 13,
  DPI_APP_GITHUB = 14,
  DPI_APP_GMAIL = 15,
  DPI_APP_QQ = 16,
  DPI_APP_WECHAT = 17,
  DPI_APP_PINTEREST = 18,
  DPI_APP_LENOVO = 19,
  DPI_APP_LINKEDIN = 20,
  DPI_APP_SKYPE = 21,
  DPI_APP_MICROSOFT = 22,
  DPI_APP_NETFLIX = 23,
  DPI_APP_NOKIA = 24,
  DPI_APP_NVIDIA = 25,
  DPI_APP_OFFICE = 26,
  DPI_APP_ORACLE = 27,
  DPI_APP_OUTLOOK = 28,
  DPI_APP_PANDORA = 29,
  DPI_APP_PAYPAL = 30,
  DPI_APP_SINA = 31,
  DPI_APP_SOGOU = 32,
  DPI_APP_SYMANTEC = 33,
  DPI_APP_TAOBAO = 34,
  DPI_APP_TWITTER = 35,
  DPI_APP_UPS = 36,
  DPI_APP_VISA = 37,
  DPI_APP_MCAFEE = 38,
  DPI_APP_VMWARE = 39,
  DPI_APP_WORDPRESS = 40,
  DPI_APP_ADOBE = 41,
  DPI_APP_AKAMAI = 42,
  DPI_APP_ALIENVAULT = 43,
  DPI_APP_BITCOMET = 44,
  DPI_APP_CHECKPOINT = 45,
  DPI_APP_BLOOMBERG = 46,
  DPI_APP_DELL = 47,
  DPI_APP_F5 = 48,
  DPI_APP_FIREEYE = 49,
  DPI_APP_DROPBOX = 50,

  /* last app ID */
  DPI_N_APPLICATIONS = 51,
} dpi_application_id_t;

typedef struct dpi_app_match_rule_
{
  char *host;
  char *pattern;
  char *app_name;
  u32 app_id;
} dpi_app_match_rule;

#define DPI_MAX_APP_NUM DPI_N_APPLICATIONS
extern dpi_app_match_rule app_match_rules[];


#endif /* dpi_app_match_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
