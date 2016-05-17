/* This file exists to ensure that checkstyle fails... */

int fail (void)
{
    if (this_file_will_fail) {
        fail();
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
