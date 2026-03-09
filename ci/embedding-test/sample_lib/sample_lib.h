#ifndef SAMPLE_LIB_H
#define SAMPLE_LIB_H

/* Returns the picoquic version string. Used to verify that sample_lib
 * correctly links against picoquic and re-exports that dependency to
 * downstream consumers. */
const char *sample_lib_picoquic_version(void);

#endif /* SAMPLE_LIB_H */
