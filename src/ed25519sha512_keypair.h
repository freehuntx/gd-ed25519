//
// Created by shubertm on 4/19/26.
//

#ifndef ED25519SHA512_KEYPAIR_H
#define ED25519SHA512_KEYPAIR_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>

namespace godot
{

    class Ed25519SHA512Keypair : public RefCounted
    {
        GDCLASS(Ed25519SHA512Keypair, RefCounted)

      private:
        PackedByteArray private_key;
        PackedByteArray public_key;

    protected:
        static void _bind_methods();

    public:
        Ed25519SHA512Keypair();
        ~Ed25519SHA512Keypair();

        static Ref<Ed25519SHA512Keypair> generate();
        static Ref<Ed25519SHA512Keypair> from_private_key(const PackedByteArray &p_private_key);

        void set_private_key(const PackedByteArray &p_key);
        PackedByteArray get_private_key() const;

        void set_public_key(const PackedByteArray &p_key);
        PackedByteArray get_public_key() const;
    };

}
#endif //ED25519SHA512_KEYPAIR_H