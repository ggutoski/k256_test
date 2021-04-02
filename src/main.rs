fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use curv::{
        elliptic::curves::traits::{ECPoint, ECScalar},
        BigInt, FE, GE,
    };
    use k256::{ecdsa::Signature, FieldBytes};

    struct EcdsaSig {
        r: FE,
        s: FE,
    }
    impl EcdsaSig {
        fn verify(&self, pubkey: &GE, msg: &FE) -> bool {
            let s_inv = self.s.invert();
            let randomizer = GE::generator() * (*msg * s_inv) + *pubkey * (self.r * s_inv);
            self.r == ECScalar::from(&randomizer.x_coor().unwrap().mod_floor(&FE::q()))
        }
    }

    #[test]
    fn k256() {
        let num_trials = 100;
        for i in 0..num_trials {
            println!("trial {} of {}...", i, num_trials);

            // make a signature using curv
            let msg: [u8; 1] = [42];
            let msg = &msg[..];
            let msg_fe: FE = ECScalar::from(&BigInt::from(msg));
            let sk = FE::new_random();
            let pk = GE::generator() * sk;
            let k = FE::new_random();
            let randomizer = GE::generator() * k.invert();
            let r: FE = ECScalar::from(&randomizer.x_coor().unwrap().mod_floor(&FE::q()));
            let s = k * (msg_fe + sk * r);
            let sig = EcdsaSig { r, s };
            assert!(sig.verify(&pk, &msg_fe));

            // import the signature using k256 and check round-trip
            let (r, s) = (&sig.r.to_big_int(), &sig.s.to_big_int());
            let (r_old, s_old) = (r.clone(), s.clone());
            let (r, s): (Vec<u8>, Vec<u8>) = (r.into(), s.into());
            let (r, s): (&[u8], &[u8]) = (&r, &s);
            let (r, s): (FieldBytes, FieldBytes) =
                (*FieldBytes::from_slice(r), *FieldBytes::from_slice(s));
            let ksig = Signature::from_scalars(r, s).unwrap();
            // let der_sig = ksig.to_asn1();
            // let der_bytes = der_sig.as_bytes();
            // println!("serialized sig: {:?}", der_bytes);
            let (r, s) = (ksig.r(), ksig.s());
            let (r, s): (FieldBytes, FieldBytes) = (From::from(r), From::from(s));
            let (r, s) = (r.as_slice(), s.as_slice());
            let (r, s): (BigInt, BigInt) = (BigInt::from(r), BigInt::from(s));
            assert_eq!(r, r_old);
            assert_eq!(s, s_old);
        }
    }
}
