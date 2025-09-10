/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 */


#ifndef SRC_VNET_TLS_TLS_TEST_H_
#define SRC_VNET_TLS_TLS_TEST_H_

/*
 * TLS server cert and keys to be used for testing only
 */
static const char test_srv_crt_rsa[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIID5zCCAs+gAwIBAgIJALeMYCEHrTtJMA0GCSqGSIb3DQEBCwUAMIGJMQswCQYD\r\n"
  "VQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQK\r\n"
  "DAVDaXNjbzEOMAwGA1UECwwFZmQuaW8xFjAUBgNVBAMMDXRlc3R0bHMuZmQuaW8x\r\n"
  "IjAgBgkqhkiG9w0BCQEWE3ZwcC1kZXZAbGlzdHMuZmQuaW8wHhcNMTgwMzA1MjEx\r\n"
  "NTEyWhcNMjgwMzAyMjExNTEyWjCBiTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB\r\n"
  "MREwDwYDVQQHDAhTYW4gSm9zZTEOMAwGA1UECgwFQ2lzY28xDjAMBgNVBAsMBWZk\r\n"
  "LmlvMRYwFAYDVQQDDA10ZXN0dGxzLmZkLmlvMSIwIAYJKoZIhvcNAQkBFhN2cHAt\r\n"
  "ZGV2QGxpc3RzLmZkLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
  "4C1k8a1DuStgggqT4o09fP9sJ2dC54bxhS/Xk2VEfaIZ222WSo4X/syRVfVy9Yah\r\n"
  "cpI1zJ/RDxaZSFhgA+nPZBrFMsrULkrdAOpOVj8eDEp9JuWdO2ODSoFnCvLxcYWB\r\n"
  "Yc5kHryJpEaGJl1sFQSesnzMFty/59ta0stk0Fp8r5NhIjWvSovGzPo6Bhz+VS2c\r\n"
  "ebIZh4x1t2hHaFcgm0qJoJ6DceReWCW8w+yOVovTolGGq+bpb2Hn7MnRSZ2K2NdL\r\n"
  "+aLXpkZbS/AODP1FF2vTO1mYL290LO7/51vJmPXNKSDYMy5EvILr5/VqtjsFCwRL\r\n"
  "Q4jcM/+GeHSAFWx4qIv0BwIDAQABo1AwTjAdBgNVHQ4EFgQUWa1SOB37xmT53tZQ\r\n"
  "aXuLLhRI7U8wHwYDVR0jBBgwFoAUWa1SOB37xmT53tZQaXuLLhRI7U8wDAYDVR0T\r\n"
  "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoUht13W4ya27NVzQuCMvqPWL3VM4\r\n"
  "3xbPFk02FaGz/WupPu276zGlzJAZrbuDcQowwwU1Ni1Yygxl96s1c2M5rHDTrOKG\r\n"
  "rK0hbkSFBo+i6I8u4HiiQ4rYmG0Hv6+sXn3of0HsbtDPGgWZoipPWDljPYEURu3e\r\n"
  "3HRe/Dtsj9CakBoSDzs8ndWaBR+f4sM9Tk1cjD46Gq2T/qpSPXqKxEUXlzhdCAn4\r\n"
  "twub17Bq2kykHpppCwPg5M+v30tHG/R2Go15MeFWbEJthFk3TZMjKL7UFs7fH+x2\r\n"
  "wSonXb++jY+KmCb93C+soABBizE57g/KmiR2IxQ/LMjDik01RSUIaM0lLA==\r\n"
  "-----END CERTIFICATE-----\r\n";
static const u32 test_srv_crt_rsa_len = sizeof (test_srv_crt_rsa);

static const char test_srv_key_rsa[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgLWTxrUO5K2CC\r\n"
  "CpPijT18/2wnZ0LnhvGFL9eTZUR9ohnbbZZKjhf+zJFV9XL1hqFykjXMn9EPFplI\r\n"
  "WGAD6c9kGsUyytQuSt0A6k5WPx4MSn0m5Z07Y4NKgWcK8vFxhYFhzmQevImkRoYm\r\n"
  "XWwVBJ6yfMwW3L/n21rSy2TQWnyvk2EiNa9Ki8bM+joGHP5VLZx5shmHjHW3aEdo\r\n"
  "VyCbSomgnoNx5F5YJbzD7I5Wi9OiUYar5ulvYefsydFJnYrY10v5otemRltL8A4M\r\n"
  "/UUXa9M7WZgvb3Qs7v/nW8mY9c0pINgzLkS8guvn9Wq2OwULBEtDiNwz/4Z4dIAV\r\n"
  "bHioi/QHAgMBAAECggEBAMzGipP8+oT166U+NlJXRFifFVN1DvdhG9PWnOxGL+c3\r\n"
  "ILmBBC08WQzmHshPemBvR6DZkA1H23cV5JTiLWrFtC00CvhXsLRMrE5+uWotI6yE\r\n"
  "iofybMroHvD6/X5R510UX9hQ6MHu5ShLR5VZ9zXHz5MpTmB/60jG5dLx+jgcwBK8\r\n"
  "LuGv2YB/WCUwT9QJ3YU2eaingnXtz/MrFbkbltrqlnBdlD+kTtw6Yac9y1XuuQXc\r\n"
  "BPeulLNDuPolJVWbUvDBZrpt2dXTgz8ws1sv+wCNE0xwQJsqW4Nx3QkpibUL9RUr\r\n"
  "CVbKlNfa9lopT6nGKlgX69R/uH35yh9AOsfasro6w0ECgYEA82UJ8u/+ORah+0sF\r\n"
  "Q0FfW5MTdi7OAUHOz16pUsGlaEv0ERrjZxmAkHA/VRwpvDBpx4alCv0Hc39PFLIk\r\n"
  "nhSsM2BEuBkTAs6/GaoNAiBtQVE/hN7awNRWVmlieS0go3Y3dzaE9IUMyj8sPOFT\r\n"
  "5JdJ6BM69PHKCkY3dKdnnfpFEuECgYEA68mRpteunF1mdZgXs+WrN+uLlRrQR20F\r\n"
  "ZyMYiUCH2Dtn26EzA2moy7FipIIrQcX/j+KhYNGM3e7MU4LymIO29E18mn8JODnH\r\n"
  "sQOXzBTsf8A4yIVMkcuQD3bfb0JiUGYUPOidTp2N7IJA7+6Yc3vQOyb74lnKnJoO\r\n"
  "gougPT2wS+cCgYAn7muzb6xFsXDhyW0Tm6YJYBfRS9yAWEuVufINobeBZPSl2cN1\r\n"
  "Jrnw+HlrfTNbrJWuJmjtZJXUXQ6cVp2rUbjutNyRV4vG6iRwEXYQ40EJdkr1gZpi\r\n"
  "CHQhuShuuPih2MNAy7EEbM+sXrDjTBR3bFqzuHPzu7dp+BshCFX3lRfAAQKBgGQt\r\n"
  "K5i7IhCFDjb/+3IPLgOAK7mZvsvZ4eXD33TQ2eZgtut1PXtBtNl17/b85uv293Fm\r\n"
  "VDISVcsk3eLNS8zIiT6afUoWlxAwXEs0v5WRfjl4radkGvgGiJpJYvyeM67877RB\r\n"
  "EDSKc/X8ESLfOB44iGvZUEMG6zJFscx9DgN25iQZAoGAbyd+JEWwdVH9/K3IH1t2\r\n"
  "PBkZX17kNWv+iVM1WyFjbe++vfKZCrOJiyiqhDeEqgrP3AuNMlaaduC3VRC3G5oV\r\n"
  "Mj1tlhDWQ/qhvKdCKNdIVQYDE75nw+FRWV8yYkHAnXYW3tNoweDIwixE0hkPR1bc\r\n"
  "oEjPLVNtx8SOj/M4rhaPT3I=\r\n" "-----END PRIVATE KEY-----\r\n";
static const u32 test_srv_key_rsa_len = sizeof (test_srv_key_rsa);

/*
 * TLS test CA to used for testing only
 */
static const char test_ca_chain_rsa[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDlTCCAn2gAwIBAgIUMZO3VeOey8A1oB6tp8gx4FXw62gwDQYJKoZIhvcNAQEL\r\n"
  "BQAwWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhTYW4gSm9z\r\n"
  "ZTEOMAwGA1UECgwFQ2lzY28xGzAZBgNVBAMMEkZkLmlvIFRlc3QgUm9vdCBDQTAe\r\n"
  "Fw0yNTA5MTEwNjI1MTVaFw0zNTA5MDkwNjI1MTVaMFoxCzAJBgNVBAYTAlVTMQsw\r\n"
  "CQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxDjAMBgNVBAoMBUNpc2NvMRsw\r\n"
  "GQYDVQQDDBJGZC5pbyBUZXN0IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\r\n"
  "DwAwggEKAoIBAQDHiQEu2NeUzmhTuPAFoJdRs8EyWmLUbu1HCaBGrmRUqLoPbAms\r\n"
  "GSowFSHJSE/jQ8d84dMZAzHQxybEzlg14eM6JgpMkzUITZj0IhZB58FiPqEOK7hT\r\n"
  "pV9nKGJkWJMm9srHo5oUwx3L8L3JZu1uaRj00c9GyD5ApvF+vmHnZv88XidR1f+m\r\n"
  "yIiuw6Pkb2GrbdGaX08WdUXVv5PrRqFAJaqXMgXCijRucbpXRBYwX1oPdrE7U+Ho\r\n"
  "uIVA6XyTp+3HwkGsV64oH3WTTIDZksgZMVQq8o9CF9eEXRjoPa5PtDRPs9LyGBid\r\n"
  "tdrHwB+++HdQU2dNbdS08KdMD/UFg4MAJpqvAgMBAAGjUzBRMB0GA1UdDgQWBBRy\r\n"
  "XX+uRpAbb8FB70rXIxWHbkAt6jAfBgNVHSMEGDAWgBRyXX+uRpAbb8FB70rXIxWH\r\n"
  "bkAt6jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAEv8yK7WGJ\r\n"
  "Zinpi5w736eCaCoSJDnIFZlQ6MHI5Jn9SSKudsGaEBSvicGcD5dkJLIdMEqFBJ6/\r\n"
  "bm8XfiDa9HUR87LfWA0qVO7hiQ0Xvvf9e1lOM/+e0JTcS2nqNajFBzuWD5OA8s8w\r\n"
  "6BdOerk7IxMw2cpwDmJ+7Nsc0yd7XRgUSyooyo3YcsvhPCg0v/pmGSbVu0nhG7sE\r\n"
  "M8DaebCc7JVpsKVfY676IwDQejte35H3jzbMOOLlHKaXDhU9Xf3eEDEfSYyM7shK\r\n"
  "5QHEw0X14TSO29Y832m3rwAizZOwLy0CpVPjIVju4qkGAzEdk4kg06NQHYlHhDA1\r\n"
  "0WNb4tBLb2N2\r\n"
  "-----END CERTIFICATE-----\r\n"
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDQzCCAisCFCfFYwTSvtLo+7AhR/fDRFffGmTaMA0GCSqGSIb3DQEBCwUAMFox\r\n"
  "CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxDjAM\r\n"
  "BgNVBAoMBUNpc2NvMRswGQYDVQQDDBJGZC5pbyBUZXN0IFJvb3QgQ0EwHhcNMjUw\r\n"
  "OTExMDYyNzM5WhcNMzUwOTA5MDYyNzM5WjBiMQswCQYDVQQGEwJVUzELMAkGA1UE\r\n"
  "CAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQKDAVDaXNjbzEjMCEGA1UE\r\n"
  "AwwaRmQuaW8gVGVzdCBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUA\r\n"
  "A4IBDwAwggEKAoIBAQCrfov0g9Ls1zV0c5tp6oxf+zGIgrd6Jg45KxKZwrRA0EN5\r\n"
  "kHtyso1OZdQbJETUIj0cs7qLenjCO4r6c0T7cA5a/VqJUgvFhH4N0oMiH5wcL9yZ\r\n"
  "m1SX5zdz7PhwBAzCyMkbvrz95243D5KLbYAMizMGx0KyHXzrqL6M+Tr1xYs2kjNj\r\n"
  "6zq2I04FXbyJnwIj+D7yQ7fyvbKiZNWNstbcDhS3DvyHbAsaCv2NiB5Gelp0iEP3\r\n"
  "HI6D1WEJiEWa8rgOtAP42WKFbjF1N7UbFUINpYvzckBIH0h7x9f/+Ocs2R4KNQLu\r\n"
  "r8Lj+NGSQkb+KkRwPF9rOy94IViUyp/yfz1B2l4ZAgMBAAEwDQYJKoZIhvcNAQEL\r\n"
  "BQADggEBAD6Dw0Kv+nnu6I4lmj50zTsArAwlQDfy+pwD3QBByvUVIkGOwWpKrMUC\r\n"
  "rAb4sNi3LYoAaGCjrFgcArpuAgireirU0ilfovDipwiXKUGLtTzOL0ZqCqi4wynR\r\n"
  "7UYh3eaHPQ0LkH+WFrrLCfRu/3TngQHDEiKaL7aug7/q/ZXQ88hTWobws7oHBnKc\r\n"
  "m5ykWmmD2JRRKu7Mg5dyzlqlI2AkMnQMrX0voTR/KE16qhbMyovNSsH+PuwvhbVl\r\n"
  "vFTyeC/o7Rm+U+JkaFA/wyP/6gzfT1XFSsNY2WAWNzrsWtCf2gVWNxPvGHg6G0Yz\r\n"
  "TiCarwFKR1qNpR+qibWDni6b2gRZcs0=\r\n"
  "-----END CERTIFICATE-----\r\n";
static const u32 test_ca_chain_rsa_len = sizeof (test_ca_chain_rsa);

static const char test_ca_crl[] =
  "-----BEGIN X509 CRL-----\r\n"
  "MIIBszCBnAIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzELMAkGA1UE\r\n"
  "CAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQKDAVDaXNjbzEbMBkGA1UE\r\n"
  "AwwSRmQuaW8gVGVzdCBSb290IENBFw0yNTA5MTEwNjI4NDhaFw0yNTEwMTEwNjI4\r\n"
  "NDhaoA4wDDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAe8YmRs+VOw3M\r\n"
  "xofJCI40bt6La/1knBd3KSM91pSBAfmZReztoHHxiM0ymViv6ZnKIymn+F1JhhqU\r\n"
  "OLV7S28oCVkpB2O1zsCv8FyfAegLrvu/ipFGsemRos+YxXtC9mam8WuGFRMFXzjB\r\n"
  "PBoyZsaWspXoHlMpUqPBfagjciiJdyxCWoCwd8jVA9swgG6dxCLUup98du88ikgA\r\n"
  "huoi90QF+/qztjwoE8rngGWKdR7Re6qYrZIwGgLupxA3pGonCsTRwPKE/qrbNhMi\r\n"
  "Pqmuu8zyeaqq/EoKNmuE22AeIn2BsYslJKMKOwQ022CAAtIDjB0boBI6+IeFrStJ\r\n"
  "41u0xwNSyA==\r\n"
  "-----END X509 CRL-----\r\n";
static const u32 test_ca_crl_len = sizeof (test_ca_crl);

#endif /* SRC_VNET_TLS_TLS_TEST_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
