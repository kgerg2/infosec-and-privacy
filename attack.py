from charm.toolbox.pairinggroup import GT, PairingGroup, pair

from original_dacmacs import DACMACS


def attack():
    # Global public parameters

    groupObj = PairingGroup("SS512")
    dac = DACMACS(groupObj)
    global_public_parameters, _ = dac.setup()

    users = {}

    # Authority setup

    authorities = {}

    authority1 = "authority1"
    possible_attributes = ["ONE", "TWO"]
    dac.setupAuthority(global_public_parameters, authority1, possible_attributes, authorities)

    # User registration

    # Alice: attribute ONE
    alice = {"id": "alice", "authoritySecretKeys": {}, "keys": None}
    alice["keys"], users[alice["id"]] = dac.registerUser(global_public_parameters)
    alice_attr_keys = dac.keygen(global_public_parameters, authorities[authority1],
                                 "ONE", users[alice["id"]], alice["authoritySecretKeys"])

    # Bob: attribute TWO
    bob = {"id": "bob", "authoritySecretKeys": {}, "keys": None}
    bob["keys"], users[bob["id"]] = dac.registerUser(global_public_parameters)
    bob_attr_keys = dac.keygen(global_public_parameters, authorities[authority1],
                               "TWO", users[bob["id"]], bob["authoritySecretKeys"])

    # Encryption

    message = groupObj.random(GT)  # message to encrypt
    print(f"Message: {message}")
    policy_str = "ONE and TWO"  # doesn't matter for the attack, could be anything
    # policy_str = "ONE"
    # policy_str = "TWO"
    ciphertext = dac.encrypt(global_public_parameters, policy_str, message, authorities[authority1])

    # Perform the attack

    x_2 = users[alice["id"]]["u"]  # This shouldn't be known to alice
    a_i_s = calcualte_authority_secret(global_public_parameters,
                                       alice, alice_attr_keys,
                                       ciphertext,
                                       x_2)
    print(f"Calculated secret for authority1 (alpha_i_s): {a_i_s}")

    # Decryption by the attacker

    decrypted = ciphertext["C1"] / a_i_s
    print(f"Message decrypted by the attacker: {decrypted}")
    print(f"Attack is {'' if decrypted == message else 'not '}successful")

    # Decryption by the user

    plaintext = None

    try:
        # Decryption by alice - should fail
        token = dac.generateTK(global_public_parameters, ciphertext,
                               alice["authoritySecretKeys"], alice["keys"][0])
        assert token
        plaintext = dac.decrypt(ciphertext, token, alice["keys"][1])

        print(f"Message decrypted by alice: {plaintext}")
    except AssertionError:
        print(f"Decryption by alice failed.")

    try:
        # Decryption by bob - should succeed
        token = dac.generateTK(global_public_parameters, ciphertext,
                               bob["authoritySecretKeys"], bob["keys"][0])
        assert token
        plaintext = dac.decrypt(ciphertext, token, bob["keys"][1])

        print(f"Message decrypted by bob: {plaintext}")
    except AssertionError:
        print(f"Decryption by bob failed.")


def calcualte_authority_secret(global_public_parameters, alice, alice_attr_keys, ciphertext, x_2):
    x_1 = alice["keys"][1]

    k_1 = alice_attr_keys["K"]
    k_3 = alice_attr_keys["R"]

    c2 = ciphertext["C2"]
    c3 = ciphertext["C3"]

    # a_i_s = x_1 * k_1 * c_1 - x_1 * k_3 * c_2 - x_1 * x_2 * g * c_1
    temp1 = pair(k_1, c2) ** x_1
    temp2 = pair(global_public_parameters["g_a"], c2) ** (x_1 * x_2) * pair(k_3, c3) ** x_1
    return temp1 / temp2  # This is the secret key for the authority


if __name__ == "__main__":
    attack()
