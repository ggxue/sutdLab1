import binascii
from collections import Counter

def decipher_substitution_cipher(hex_string):
    # Convert hex string to ASCII
    ascii_string = binascii.unhexlify(hex_string).decode()

    # Calculate letter frequencies
    letter_frequencies = Counter(ascii_string.lower())

    # Define most common letters in English
    english_letters = "etaoinshrdlcumwfgypbvkjxqz"

    # Define dictionary to store mapping of ciphered letters to deciphered letters
    letter_mapping = {}

    # Map most frequent letters in ASCII string to most common letters in English
    for ciphered_letter, _ in letter_frequencies.most_common():
        letter_mapping[ciphered_letter] = english_letters[0]
        english_letters = english_letters[1:]

    # Substitute ciphered letters with deciphered letters
    deciphered_string = ''.join(letter_mapping.get(c, c) for c in ascii_string)

    return deciphered_string

# Example usage:
hex_string = "59c55454591e5b181eff0bed747762fa24ed1e5b1077fa245b745b54c50e1e5b54f61e181e5b2774015b745bff1e74185b59c55454591e5baac518595b27f6fa5b2774015b59fa931eff6283695b1e931e18695bfa241e5b27f6fa5b59fafaf21eff5b74545bf61e18d85b8310545b0efa01545bfa175b7459595b83695bf61e1862aa187424ff0efa54f61e18d85b7424ff5b54f61e181e5b2774015b24fa54f6c524aa5b54f674545b01f61e5b27fa1059ff5b24fa545bf674931e62aac5931e245b54fa5b54f61e5bedf6c559ff115b5bfa24ed1e5b01f61e5baa74931e5bf61e185b745b59c55454591e5bed74775bfa175b181eff62931e59931e54d85b27f6c5edf65b0110c5541eff5bf61e185b01fa5b271e59595b54f674545b01f61e5b27fa1059ff5b241e931e185b271e74186274246954f6c524aa5b1e59011e115b5b01fa5b01f61e5b2774015b7459277469015bed7459591eff5b59c55454591e5b181eff0bed74771162fa241e5bff74695bf61e185b0efa54f61e185b0174c5ff5b54fa5bf61e18d85bedfa0e1ed85b59c55454591e5b181eff0bed7477d85bf61e181e62c5015b745b77c51eed1e5bfa175bed74f21e5b7424ff5b745b83fa5454591e5bfa175b27c5241e115b5b5474f21e5b54f61e0e5b54fa5b69fa101862aa187424ff0efa54f61e18d85b01f61e5bc5015bc559595b7424ff5b271e74f2d85b7424ff5b54f61e695b27c559595bfffa5bf61e185baafafaff1162011e545bfa10545b831e17fa181e5bc5545baa1e54015bf6fa54d85b7424ff5b27f61e245b69fa105b74181e5baafac524aad85b277459f26224c5ed1e59695b7424ff5bea10c51e5459695b7424ff5bfffa5b24fa545b1810245bfa17175b54f61e5b777454f6d85bfa185b69fa105b0e746962177459595b7424ff5b83181e74f25b54f61e5b83fa5454591ed85b7424ff5b54f61e245b69fa10185baa187424ff0efa54f61e185b27c5595962aa1e545b24fa54f6c524aa115b5b7424ff5b27f61e245b69fa105baafa5bc52454fa5bf61e185b18fafa0ed85bfffa2452545b17fa18aa1e546254fa5b017469d85baafafaff0b0efa1824c524aad85b7424ff5bfffa2452545b771e1e775bc52454fa5b1e931e18695bedfa18241e185b831e17fa181e6269fa105bfffa5bc5541162c55b27c559595b5474f21e5baa181e74545bed74181ed85b0174c5ff5b59c55454591e5b181eff0bed74775b54fa5bf61e185b0efa54f61e18d85b7424ff62aa74931e5bf61e185bf67424ff5bfa245bc554116254f61e5baa187424ff0efa54f61e185b59c5931eff5bfa10545bc5245b54f61e5b27fafaffd85bf67459175b745b591e74aa101e5b1718fa0e5b54f61e6293c5595974aa1ed85b7424ff5b021001545b74015b59c55454591e5b181eff0bed74775b1e24541e181eff5b54f61e5b27fafaffd85b745b27fa5917620e1e545bf61e18115b5b181eff0bed74775bffc5ff5b24fa545bf224fa275b27f674545b745b27c5edf21eff5bed181e745410181e5bf61e5b277401d8627424ff5b2774015b24fa545b74545b7459595b74171874c5ff5bfa175bf6c50e1162aafafaff0bff7469d85b59c55454591e5b181eff0bed7477d85b0174c5ff5bf61e116254f67424f25b69fa105bf2c524ff5969d85b27fa5917116227f6c554f61e185b742774695b01fa5b1e74185969d85b59c55454591e5b181eff0bed7477bb6254fa5b0e695baa187424ff0efa54f61e185201116227f674545bf674931e5b69fa105baafa545bc5245b69fa10185b747718fa24bb62ed74f21e5b7424ff5b27c5241e115b5b691e01541e18ff74695b2774015b8374f2c524aa0bff7469d85b01fa5b77fafa185b01c5edf262aa187424ff0efa54f61e185bc5015b54fa5bf674931e5b01fa0e1e54f6c524aa5baafafaffd85b54fa5b0e74f21e5bf61e185b015418fa24aa1e18116227f61e181e5bfffa1e015b69fa10185baa187424ff0efa54f61e185b59c5931ed85b59c55454591e5b181eff0bed7477bb62745baafafaff5bea107418541e185bfa175b745b591e74aa101e5b17741854f61e185bfa245bc5245b54f61e5b27fafaff115b5bf61e185bf6fa10011e6201547424ff015b1024ff1e185b54f61e5b54f6181e1e5b597418aa1e5bfa74f20b54181e1e01d85b54f61e5b2410540b54181e1e015b74181e5b0210015462831e59fa27115b5b69fa105b0110181e59695b0e1001545bf224fa275bc554d85b181e7759c51eff5b59c55454591e5b181eff0bed7477116254f61e5b27fa59175b54f6fa10aaf6545b54fa5bf6c50e011e5917d85b27f674545b745b541e24ff1e185b69fa1024aa5bed181e745410181e115b5b27f674545b746224c5ed1e5b7759100e775b0efa1054f6171059d85b01f61e5b27c559595b831e5b831e54541e185b54fa5b1e74545b54f674245b54f61e5bfa59ff6227fa0e7424115b5bc55b0e1001545b74ed545bed18741754c55969d85b01fa5b74015b54fa5bed7454edf65b83fa54f6115b5b01fa5bf61e5b277459f21eff6217fa185b745b01f6fa18545b54c50e1e5b83695b54f61e5b01c5ff1e5bfa175b59c55454591e5b181eff0bed7477d85b7424ff5b54f61e245bf61e620174c5ffd85b011e1e5b59c55454591e5b181eff0bed7477d85bf6fa275b77181e5454695b54f61e5b1759fa271e18015b74181e5b7483fa10545bf61e181e116227f6695bfffa5b69fa105b24fa545b59fafaf25b18fa1024ff115b5bc55b831e59c51e931ed85b54fafad85b54f674545b69fa105bfffa5b24fa5462f61e74185bf6fa275b01271e1e5459695b54f61e5b59c55454591e5b83c518ff015b74181e5b01c524aac524aa115b5b69fa105b277459f25baa1874931e5969627459fa24aa5b74015bc5175b69fa105b271e181e5baafac524aa5b54fa5b01edf6fafa59d85b27f6c5591e5b1e931e186954f6c524aa5b1e59011e5bfa105462f61e181e5bc5245b54f61e5b27fafaff5bc5015b0e1e181869116259c55454591e5b181eff0bed74775b1874c5011eff5bf61e185b1e691e01d85b7424ff5b27f61e245b01f61e5b0174275b54f61e5b011024831e740e0162ff7424edc524aa5bf61e181e5b7424ff5b54f61e181e5b54f618fa10aaf65b54f61e5b54181e1e01d85b7424ff5b77181e5454695b1759fa271e180162aa18fa27c524aa5b1e931e186927f61e181ed85b01f61e5b54f6fa10aaf654d85b01107777fa011e5bc55b5474f21e5baa187424ff0efa54f61e185b746217181e01f65b24fa011eaa7469115b5b54f674545b27fa1059ff5b77591e74011e5bf61e185b54fafa115b5bc5545bc5015b01fa5b1e741859695bc5245b54f61e62ff74695b54f674545bc55b01f67459595b0154c559595baa1e545b54f61e181e5bc5245baafafaff5b54c50e1e115b5b7424ff5b01fa5b01f61e5b187424621718fa0e5b54f61e5b777454f65bc52454fa5b54f61e5b27fafaff5b54fa5b59fafaf25b17fa185b1759fa271e1801115b5b7424ff5b27f61e241e931e186201f61e5bf674ff5b77c5edf21eff5bfa241ed85b01f61e5b177424edc51eff5b54f674545b01f61e5b0174275b745b0154c559595b77181e5454c51e185bfa241e6217741854f61e185bfa24d85b7424ff5b1874245b7417541e185bc554d85b7424ff5b01fa5baafa545bff1e1e771e185b7424ff5bff1e1e771e185bc52454fa6254f61e5b27fafaff11620e1e742427f6c5591e5b54f61e5b27fa59175b1874245b01541874c5aaf6545b54fa5b54f61e5baa187424ff0efa54f61e1852015bf6fa10011e5b7424ff62f224faedf21eff5b74545b54f61e5bfffafa18116227f6fa5bc5015b54f61e181ebb6259c55454591e5b181eff0bed7477d85b181e7759c51eff5b54f61e5b27fa5917115b5b01f61e5bc5015b8318c524aac524aa5bed74f21e5b7424ff6227c5241e115b5bfa771e245b54f61e5bfffafa18116259c517545b54f61e5b597454edf6d85bed7459591eff5bfa10545b54f61e5baa187424ff0efa54f61e18d85bc55b740e5b54fafa5b271e74f2d85b7424ff62ed742424fa545baa1e545b1077116254f61e5b27fa59175b59c517541eff5b54f61e5b597454edf6d85b54f61e5bfffafa185b0177187424aa5bfa771e24d85b7424ff5b27c554f6fa105462017469c524aa5b745b27fa18ff5bf61e5b271e24545b01541874c5aaf6545b54fa5b54f61e5baa187424ff0efa54f61e1852015b831effd85b7424ff62ff1e93fa10181eff5bf61e18115b5b54f61e245bf61e5b7710545bfa245bf61e185bed59fa54f61e01d85bff181e01011eff5bf6c50e011e59175bc52462f61e185bed7477d85b5974c5ff5bf6c50e011e59175bc5245b831eff5b7424ff5bff181e275b54f61e5bed10185474c52401116259c55454591e5b181eff0bed7477d85bf6fa271e931e18d85bf674ff5b831e1e245b18102424c524aa5b7483fa10545b77c5edf2c524aa5b1759fa271e1801d8627424ff5b27f61e245b01f61e5bf674ff5baa7454f61e181eff5b01fa5b0e7424695b54f674545b01f61e5bedfa1059ff5bed741818696224fa5b0efa181ed85b01f61e5b181e0e1e0e831e181eff5bf61e185baa187424ff0efa54f61e18d85b7424ff5b011e545bfa10545bfa245b54f61e622774695b54fa5bf61e18116201f61e5b2774015b0110187718c5011eff5b54fa5b17c524ff5b54f61e5bedfa545474aa1e0bfffafa185b01547424ffc524aa5bfa771e24d85b7424ff6227f61e245b01f61e5b271e24545bc52454fa5b54f61e5b18fafa0ed85b01f61e5bf674ff5b0110edf65b745b0154187424aa1e5b171e1e59c524aa5b54f674546201f61e5b0174c5ff5b54fa5bf61e18011e5917d85bfaf65bff1e7418d85bf6fa275b10241e7401695bc55b171e1e595b54fa0bff7469d85b7424ff5b745462fa54f61e185b54c50e1e015bc55b59c5f21e5b831ec524aa5b27c554f65baa187424ff0efa54f61e185b01fa5b0e10edf6115b5b01f61e5bed7459591eff62fa1054d85baafafaff5b0efa1824c524aad85b8310545b181eed1ec5931eff5b24fa5b742401271e18115b5b01fa5b01f61e5b271e24545b54fa5b54f61e62831eff5b7424ff5bff181e275b8374edf25b54f61e5bed10185474c52401115b5b54f61e181e5b5974695bf61e185baa187424ff0efa54f61e185b27c554f662f61e185bed74775b771059591eff5b1774185bfa931e185bf61e185b1774ed1ed85b7424ff5b59fafaf2c524aa5b931e18695b0154187424aa1e1162faf6d85baa187424ff0efa54f61e18d85b01f61e5b0174c5ffd85b27f674545b83c5aa5b1e7418015b69fa105bf674931e116254f61e5b831e54541e185b54fa5bf61e74185b69fa105b27c554f6d85b0e695bedf6c559ffd85b2774015b54f61e5b181e7759691162831054d85baa187424ff0efa54f61e18d85b27f674545b83c5aa5b1e691e015b69fa105bf674931ed85b01f61e5b0174c5ff116254f61e5b831e54541e185b54fa5b011e1e5b69fa105b27c554f6d85b0e695bff1e74181162831054d85baa187424ff0efa54f61e18d85b27f674545b597418aa1e5bf67424ff015b69fa105bf674931e116254f61e5b831e54541e185b54fa5bf610aa5b69fa105b27c554f61162faf6d85b831054d85baa187424ff0efa54f61e18d85b27f674545b745b541e1818c583591e5b83c5aa5b0efa1054f65b69fa105bf674931e116254f61e5b831e54541e185b54fa5b1e74545b69fa105b27c554f611627424ff5b01ed7418ed1e59695bf674ff5b54f61e5b27fa59175b0174c5ff5b54f6c501d85b54f674245b27c554f65bfa241e5b83fa1024ff5bf61e5b27740162fa10545bfa175b831eff5b7424ff5b0127745959fa271eff5b10775b181eff0bed7477116227f61e245b54f61e5b27fa59175bf674ff5b7477771e74011eff5bf6c5015b7477771e54c5541ed85bf61e5b5974695bfffa27245b74aa74c5245bc5246254f61e5b831effd85b171e59595b7401591e1e775b7424ff5b831eaa74245b54fa5b0124fa181e5b931e18695b59fa10ff115b5b54f61e62f6102454010e74245b2774015b021001545b77740101c524aa5b54f61e5bf6fa10011ed85b7424ff5b54f6fa10aaf6545b54fa5bf6c50e011e5917d85bf6fa276254f61e5bfa59ff5b27fa0e74245bc5015b0124fa18c524aa115b5bc55b0e1001545b021001545b011e1e5bc5175b01f61e5b27742454015b74246954f6c524aa116201fa5bf61e5b271e24545bc52454fa5b54f61e5b18fafa0ed85b7424ff5b27f61e245bf61e5bed740e1e5b54fa5b54f61e5b831effd85bf61e5b0174276254f674545b54f61e5b27fa59175b2774015b5969c524aa5bc5245bc554115b5bfffa5bc55b17c524ff5b69fa105bf61e181ed85b69fa105bfa59ff6201c524241e18d85b0174c5ff5bf61e115b5bc55bf674931e5b59fa24aa5b01fa10aaf6545b69fa10115b5b54f61e245b021001545b74015bf61e5b2774015baafac524aa6254fa5b17c5181e5b74545bf6c50ed85bc5545bfaeded1018181eff5b54fa5bf6c50e5b54f674545b54f61e5b27fa59175b0ec5aaf6545bf674931e62ff1e93fa10181eff5b54f61e5baa187424ff0efa54f61e18d85b7424ff5b54f674545b01f61e5b0ec5aaf6545b0154c559595b831e5b0174931effd85b01fa62f61e5bffc5ff5b24fa545b17c5181ed85b8310545b54fafaf25b745b7774c5185bfa175b01edc50101fa1801d85b7424ff5b831eaa74245b54fa5bed105462fa771e245b54f61e5b0154fa0e74edf65bfa175b54f61e5b01591e1e77c524aa5b27fa5917115b5b27f61e245bf61e5bf674ff5b0e74ff1e5b5427fa620124c57701d85bf61e5b0174275b54f61e5b59c55454591e5b181eff0bed74"
deciphered_string = decipher_substitution_cipher(hex_string)
print(deciphered_string)