#!/usr/bin/env python
import os
import sys

localEnv = Environment()
if "CC" in os.environ:
    localEnv["CC"] = os.environ["CC"]
if "CXX" in os.environ:
    localEnv["CXX"] = os.environ["CXX"]
localEnv["build_profile"] = "build_profile.json"

opts = Variables([], ARGUMENTS)
opts.Add(EnumVariable('target', 'Build target', 'template_debug', allowed_values=('template_debug', 'template_release')))
opts.Add(EnumVariable('platform', 'Target platform', '', allowed_values=('', 'linux', 'macos', 'windows', 'android', 'ios', 'web')))
opts.Add(EnumVariable('arch', 'Target architecture', '', allowed_values=('', 'x86_32', 'x86_64', 'arm32', 'arm64', 'rv64', 'ppc32', 'ppc64', 'wasm32', 'universal')))
opts.Update(localEnv)

# Add Godot-cpp to the build
env = localEnv.Clone()
env = SConscript("godot-cpp/SConstruct", { "env": env })
env.Append(CPPPATH=["src"])

# Define the sources
sources = Glob("src/*.cpp") + Glob("src/*.c")

# Generate doc data for in-editor documentation
if env["target"] in ["editor", "template_debug"]:
    doc_data = env.GodotCPPDocData("src/gen/doc_data.gen.cpp", source=Glob("doc_classes/*.xml"))
    sources.append(doc_data)

# Define the library name
lib_name = "ed25519"
env["SHLIBPREFIX"] = ""

platform = env["platform"]
arch = env["arch"]

if platform == "linux":
    if arch == "x86_64":
        out_folder = "linux64"
    elif arch == "x86_32":
        out_folder = "linux32"
    elif arch == "arm64":
        out_folder = "linuxarm64"
    else:
        out_folder = "linux" + str(arch)
elif platform == "windows":
    if arch == "x86_64":
        out_folder = "win64"
    elif arch == "x86_32":
        out_folder = "win32"
    else:
        out_folder = "win" + str(arch)
elif platform == "macos":
    out_folder = "osx"
elif platform == "android":
    if arch == "arm64":
        out_folder = "androidarm64"
    elif arch == "x86_64":
        out_folder = "androidx64"
    else:
        out_folder = "android" + str(arch)
elif platform == "web":
    out_folder = "web"
else:
    out_folder = "bin"

# Build the library
library = env.SharedLibrary(
    "project/addons/ed25519/" + out_folder + "/" + lib_name + "{}{}".format(env["suffix"], env["SHLIBSUFFIX"]),
    sources,
)

Default(library)
