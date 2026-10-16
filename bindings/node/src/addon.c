/*
 * The Node addon over the soroauth C ABI.
 *
 * It is deliberately dumb: every function is a string in, string out call into
 * the Go shared library (bindings/c), returning the JSON envelope unchanged.
 * The envelope is parsed and turned into a typed exception in JS
 * (lib/errors.js), so the C layer holds no policy — there is one place that
 * decides what a `kind` means, and it is not here.
 *
 * The library is loaded at runtime with dlopen rather than linked at build
 * time, so the addon does not bake in an install prefix: the same `.node`
 * works against a prebuilt library shipped in `prebuilds/` or one built from
 * source into `lib/`. `loadLibrary(path)` must be called once before any other
 * function.
 *
 * N-API is used on purpose: its ABI is stable across Node versions, so one
 * prebuilt addon per platform works on every supported Node, and the addon
 * itself has no V8 dependency to rebuild against.
 */

#define _GNU_SOURCE

#include <node_api.h>

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef char *(*fn_version)(void);
typedef char *(*fn_preimage)(const char *, long long, const char *);
typedef char *(*fn_payload)(const char *);
typedef char *(*fn_write_signature)(const char *, long long, const char *, const char *, const char *);
typedef char *(*fn_authorize_seed)(const char *, long long, const char *, const char *, const char *);
typedef char *(*fn_authorize_seeds)(const char *, long long, const char *, const char *, const char *);
typedef char *(*fn_inspect)(const char *);
typedef char *(*fn_analyze)(const char *, long long);
typedef char *(*fn_render)(const char *);
typedef void (*fn_free)(char *);

static void *lib_handle = NULL;

static fn_version p_version = NULL;
static fn_preimage p_preimage = NULL;
static fn_payload p_payload = NULL;
static fn_write_signature p_write_signature = NULL;
static fn_authorize_seed p_authorize_seed = NULL;
static fn_authorize_seeds p_authorize_seeds = NULL;
static fn_inspect p_inspect = NULL;
static fn_analyze p_analyze = NULL;
static fn_render p_invocation_tree = NULL;
static fn_render p_credential_tree = NULL;
static fn_free p_free = NULL;

/* throw_type throws a TypeError and returns NULL, for use as `return throw_type(...)`. */
static napi_value throw_type(napi_env env, const char *message) {
  napi_throw_type_error(env, NULL, message);
  return NULL;
}

/*
 * dup_string copies a JS string argument into a NUL-terminated malloc'd
 * buffer, or returns NULL when the argument is not a string. The caller frees.
 */
static char *dup_string(napi_env env, napi_value value) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
    return NULL;
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok) {
    return NULL;
  }
  char *buffer = (char *)malloc(length + 1);
  if (buffer == NULL) {
    return NULL;
  }
  size_t written = 0;
  if (napi_get_value_string_utf8(env, value, buffer, length + 1, &written) != napi_ok) {
    free(buffer);
    return NULL;
  }
  buffer[length] = '\0';
  return buffer;
}

/* int64_arg reads an optional integer argument, defaulting to 0. */
static long long int64_arg(napi_env env, napi_value value) {
  if (value == NULL) {
    return 0;
  }
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok) {
    return 0;
  }
  if (type == napi_undefined || type == napi_null) {
    return 0;
  }
  int64_t out = 0;
  if (napi_get_value_int64(env, value, &out) != napi_ok) {
    return 0;
  }
  return (long long)out;
}

/*
 * finish copies the library's result into a JS string and frees it. A NULL
 * result is a bug in the library, not a caller error, so it throws rather than
 * returning an undefined the caller would misread.
 */
static napi_value finish(napi_env env, char *out) {
  if (out == NULL) {
    napi_throw_error(env, NULL, "soroauth: the native library returned no result");
    return NULL;
  }
  napi_value result;
  if (napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH, &result) != napi_ok) {
    p_free(out);
    napi_throw_error(env, NULL, "soroauth: could not create a JS string from the result");
    return NULL;
  }
  p_free(out);
  return result;
}

static napi_value require_library(napi_env env) {
  if (lib_handle == NULL) {
    return throw_type(env, "soroauth: loadLibrary(path) must be called before any other function");
  }
  return NULL;
}

static napi_value LoadLibrary(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    return throw_type(env, "soroauth: loadLibrary(path) needs the shared library path");
  }
  char *path = dup_string(env, argv[0]);
  if (path == NULL) {
    return throw_type(env, "soroauth: loadLibrary(path) needs a string path");
  }

  if (lib_handle != NULL) {
    dlclose(lib_handle);
    lib_handle = NULL;
  }
  lib_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  free(path);
  if (lib_handle == NULL) {
    napi_throw_error(env, NULL, dlerror());
    return NULL;
  }

#define BIND(field, name)                                        \
  do {                                                           \
    void *symbol = dlsym(lib_handle, name);                      \
    if (symbol == NULL) {                                        \
      napi_throw_error(env, NULL, "soroauth: missing symbol " name); \
      return NULL;                                               \
    }                                                            \
    memcpy(&(field), &symbol, sizeof(void *));                   \
  } while (0)

  BIND(p_version, "SoroauthVersion");
  BIND(p_preimage, "SoroauthPreimage");
  BIND(p_payload, "SoroauthPayload");
  BIND(p_write_signature, "SoroauthWriteSignature");
  BIND(p_authorize_seed, "SoroauthAuthorizeWithSeed");
  BIND(p_authorize_seeds, "SoroauthAuthorizeWithSeeds");
  BIND(p_inspect, "SoroauthInspect");
  BIND(p_analyze, "SoroauthAnalyze");
  BIND(p_invocation_tree, "SoroauthRenderInvocations");
  BIND(p_credential_tree, "SoroauthRenderTree");
  BIND(p_free, "SoroauthFree");

#undef BIND

  napi_value ok;
  napi_get_boolean(env, true, &ok);
  return ok;
}

static napi_value Version(napi_env env, napi_callback_info info) {
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  return finish(env, p_version());
}

static napi_value Preimage(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  char *network = argc > 2 ? dup_string(env, argv[2]) : NULL;
  long long valid = argc > 1 ? int64_arg(env, argv[1]) : 0;
  if (entry == NULL || network == NULL) {
    free(entry);
    free(network);
    return throw_type(env, "soroauth: preimage(entry, validUntilLedger, networkPassphrase) needs strings");
  }
  char *out = p_preimage(entry, valid, network);
  free(entry);
  free(network);
  return finish(env, out);
}

static napi_value Payload(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *preimage = argc > 0 ? dup_string(env, argv[0]) : NULL;
  if (preimage == NULL) {
    return throw_type(env, "soroauth: payload(preimageXdr) needs a string");
  }
  char *out = p_payload(preimage);
  free(preimage);
  return finish(env, out);
}

static napi_value WriteSignature(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  char *network = argc > 2 ? dup_string(env, argv[2]) : NULL;
  char *for_address = argc > 3 ? dup_string(env, argv[3]) : NULL;
  char *signature = argc > 4 ? dup_string(env, argv[4]) : NULL;
  long long valid = argc > 1 ? int64_arg(env, argv[1]) : 0;
  if (entry == NULL || network == NULL || for_address == NULL || signature == NULL) {
    free(entry);
    free(network);
    free(for_address);
    free(signature);
    return throw_type(env, "soroauth: writeSignature(entry, validUntilLedger, networkPassphrase, forAddress, signatureScval) needs strings");
  }
  char *out = p_write_signature(entry, valid, network, for_address, signature);
  free(entry);
  free(network);
  free(for_address);
  free(signature);
  return finish(env, out);
}

static napi_value AuthorizeWithSeed(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  char *network = argc > 2 ? dup_string(env, argv[2]) : NULL;
  char *seed = argc > 3 ? dup_string(env, argv[3]) : NULL;
  char *for_address = argc > 4 ? dup_string(env, argv[4]) : NULL;
  long long valid = argc > 1 ? int64_arg(env, argv[1]) : 0;
  if (entry == NULL || network == NULL || seed == NULL || for_address == NULL) {
    free(entry);
    free(network);
    free(seed);
    free(for_address);
    return throw_type(env, "soroauth: authorizeWithSeed(entry, validUntilLedger, networkPassphrase, seedHex, forAddress) needs strings");
  }
  char *out = p_authorize_seed(entry, valid, network, seed, for_address);
  free(entry);
  free(network);
  free(seed);
  free(for_address);
  return finish(env, out);
}

static napi_value AuthorizeWithSeeds(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value argv[5];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  char *network = argc > 2 ? dup_string(env, argv[2]) : NULL;
  char *seeds = argc > 3 ? dup_string(env, argv[3]) : NULL;
  char *for_address = argc > 4 ? dup_string(env, argv[4]) : NULL;
  long long valid = argc > 1 ? int64_arg(env, argv[1]) : 0;
  if (entry == NULL || network == NULL || seeds == NULL || for_address == NULL) {
    free(entry);
    free(network);
    free(seeds);
    free(for_address);
    return throw_type(env, "soroauth: authorizeWithSeeds(entry, validUntilLedger, networkPassphrase, seedsCsv, forAddress) needs strings");
  }
  char *out = p_authorize_seeds(entry, valid, network, seeds, for_address);
  free(entry);
  free(network);
  free(seeds);
  free(for_address);
  return finish(env, out);
}

static napi_value Inspect(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  if (entry == NULL) {
    return throw_type(env, "soroauth: inspect(entry) needs a string");
  }
  char *out = p_inspect(entry);
  free(entry);
  return finish(env, out);
}

static napi_value Analyze(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  long long ledger = argc > 1 ? int64_arg(env, argv[1]) : 0;
  if (entry == NULL) {
    return throw_type(env, "soroauth: analyze(entry, currentLedger) needs a string entry");
  }
  char *out = p_analyze(entry, ledger);
  free(entry);
  return finish(env, out);
}

static napi_value RenderInvocations(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  if (entry == NULL) {
    return throw_type(env, "soroauth: renderInvocations(entry) needs a string");
  }
  char *out = p_invocation_tree(entry);
  free(entry);
  return finish(env, out);
}

static napi_value RenderTree(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  napi_value failure = require_library(env);
  if (failure != NULL) return failure;
  char *entry = argc > 0 ? dup_string(env, argv[0]) : NULL;
  if (entry == NULL) {
    return throw_type(env, "soroauth: renderTree(entry) needs a string");
  }
  char *out = p_credential_tree(entry);
  free(entry);
  return finish(env, out);
}

#define EXPORT(env, exports, name, fn)                            \
  do {                                                            \
    napi_value value;                                             \
    napi_create_function(env, name, NAPI_AUTO_LENGTH, fn, NULL, &value); \
    napi_set_named_property(env, exports, name, value);           \
  } while (0)

NAPI_MODULE_INIT() {
  EXPORT(env, exports, "loadLibrary", LoadLibrary);
  EXPORT(env, exports, "version", Version);
  EXPORT(env, exports, "preimage", Preimage);
  EXPORT(env, exports, "payload", Payload);
  EXPORT(env, exports, "writeSignature", WriteSignature);
  EXPORT(env, exports, "authorizeWithSeed", AuthorizeWithSeed);
  EXPORT(env, exports, "authorizeWithSeeds", AuthorizeWithSeeds);
  EXPORT(env, exports, "inspect", Inspect);
  EXPORT(env, exports, "analyze", Analyze);
  EXPORT(env, exports, "renderInvocations", RenderInvocations);
  EXPORT(env, exports, "renderTree", RenderTree);
  return exports;
}
