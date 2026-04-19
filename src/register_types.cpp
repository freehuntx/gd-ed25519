#include "register_types.h"

#include "ed25519.h"
#include "ed25519_keypair.h"
#include <ed25519sha512.h>
#include <ed25519sha512_keypair.h>

#include <gdextension_interface.h>
#include <godot_cpp/core/defs.hpp>
#include <godot_cpp/godot.hpp>

using namespace godot;

void initialize_ed25519_module(ModuleInitializationLevel p_level)
{
  if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE)
  {
    return;
  }

  ClassDB::register_class<Ed25519>();
  ClassDB::register_class<Ed25519Keypair>();
  ClassDB::register_class<Ed25519SHA512>();
  ClassDB::register_class<Ed25519SHA512Keypair>();
}

void uninitialize_ed25519_module(ModuleInitializationLevel p_level)
{
  if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE)
  {
    return;
  }
}

extern "C"
{
  // Initialization.
  GDExtensionBool GDE_EXPORT ed25519_library_init(GDExtensionInterfaceGetProcAddress p_get_proc_address, const GDExtensionClassLibraryPtr p_library, GDExtensionInitialization *r_initialization)
  {
    godot::GDExtensionBinding::InitObject init_obj(p_get_proc_address, p_library, r_initialization);

    init_obj.register_initializer(initialize_ed25519_module);
    init_obj.register_terminator(uninitialize_ed25519_module);
    init_obj.set_minimum_library_initialization_level(MODULE_INITIALIZATION_LEVEL_SCENE);

    return init_obj.init();
  }
}
