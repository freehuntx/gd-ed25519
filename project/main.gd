extends Node

func _ready():
	Ed25519BLAKE.test()
	Ed25519Sha512.test()
	get_tree().quit()
