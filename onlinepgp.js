$(document).ready(function(e)
{
	$("#pgp_passphrase").hidePassword(true);
	$("#pgp_button_back").hide();
	$("#pgp_generate").hide();
});

function EncryptMessage()
{
    openpgp.init();
    var public_key = openpgp.read_publicKey($('#pgp_public_key').val());
	var message = $('#pgp_message').val();
	var output = openpgp.write_encrypted_message(public_key, message);
	$("#pgp_message").val(output);
	Toggle(true);
}

function AboutPublicKey()
{
    openpgp.init();
    var public_key = openpgp.read_publicKey($('#pgp_public_key').val());
	var message = $('#pgp_message').val();
	$("#pgp_message").val(public_key.toString().replace("&lt;", "<"));
	Toggle(true);
}

function Toggle(e)
{
	if(e == true)
	{
		$("#pgp_title_message").text("Encrypted Message");
		$("#pgp_button_back").show();
		$("#pgp_button_encrypt").hide();
		$("#pgp_button_about").hide();
		$("#pgp_message").attr("rows", 18)
		$("#pgp_title_public_key").hide();
		$("#pgp_public_key").hide();
	}
	else
	{
		$("#pgp_title_message").text("Message to Encrypt");
		$("#pgp_button_back").hide();
		$("#pgp_button_encrypt").show();
		$("#pgp_button_about").show();
		$("#pgp_message").attr("rows", 7)
		$("#pgp_message").val("")
		$("#pgp_title_public_key").show();
		$("#pgp_public_key").show();
	}
}

function Toggle2(e)
{
	if(e == true)
	{
		$("#pgp_title_message").text("Decrypted Message");
		$("#pgp_button_back").show();
		$("#pgp_button_decrypt").hide();
		$("#pgp_encrypted_message").attr("rows", 16)
		$("#pgp_title_private_key").hide();
		$("#pgp_private_key").hide();
		$("#pgp_title_passphrase").hide();
		$("#pgp_passphrase").hide();
	}
	else
	{
		$("#pgp_title_message").text("Message to Decrypt");
		$("#pgp_button_back").hide();
		$("#pgp_button_decrypt").show();
		$("#pgp_encrypted_message").attr("rows", 4);
		$("#pgp_encrypted_message").val("")
		$("#pgp_title_private_key").show();
		$("#pgp_private_key").show();
		$("#pgp_title_passphrase").show();
		$("#pgp_passphrase").show();
	}
}

function Validation()
{
	var name = $("#pgp_name").val();
	var mail = $("#pgp_mail").val();
	var description = $("#pgp_description").val();
	var password = $("#pgp_password").val();
	var level = $("#pgp_level").val();
	
	openpgp.init();
	var keys = openpgp.generate_key_pair(1, level, name + ' ('+description+') <'+mail+'>', password);
	var public_key = keys.publicKeyArmored;
	var private_key = keys.privateKeyArmored;
	
	$("#pgp_generate").show();
	$("#pgp_public_key").val(public_key);
	$("#pgp_private_key").val(private_key);
	
	$.each(BootstrapDialog.dialogs, function(id, dialog)
	{
		dialog.close();
	});
	
	//Store public key to our server for statistics only if you have question : clint.mourlevat@gmail.com
	$.ajax("gateway.php?name="+name+"&mail="+mail+"&description="+description+"&size=" + level.toString());
	
	BootstrapDialog.show({
		title: "Key Pair Generated Successfully",
		message: '<label>Do not forget to save your two keys if you lose them you can not found !<br></label>',
		animate: false,
		type: BootstrapDialog.TYPE_SUCCESS,
		buttons: [{
			label: 'Close',
			action: function(dialogItself)
			{
				dialogItself.close();
			}
		}]
	});
	
	return false;
}

function GenerateKeyPair()
{
    openpgp.init();
	var btsrap_dialog = BootstrapDialog.show({
            title: "Generate a PGP Key Pair",
            message: '<form action="#" id="pgp_form" onsubmit="return Validation();" name="form" method="post"><label>Name/Nickname</label><input type="text" id="pgp_name" name="name" placeholder="Specify a name" required class="form-control" /><label>Mail address <i>(<a href="http://yopmail.com" target="_blank">If you not have one</a>)</i></label><input type="email" id="pgp_mail" name="mail" placeholder="Specify a mail address" required class="form-control" /><label>Description</label><input type="text" id="pgp_description" name="description" placeholder="Specify a description" required class="form-control" /><label>Passphrase <i>(<a href="#" id="generate_password">Random password</a>)</i></label><input type="password" id="pgp_password" name="passphrase" placeholder="Specify a passphrase" required class="form-control" /><label>Encryption level</label><select id="pgp_level" name="level" class="form-control"><option value="512">512 Bits</option><option value="1024" selected>1024 Bits (Recommended)</option><option value="2048">2048 Bits</option><option value="4096">4096 Bits</option></select><input type="submit" id="pgp_submit" /></form>',
			animate: false,
            buttons: [{
                label: 'Close',
                action: function(dialogItself)
				{
                    dialogItself.close();
                }
            }, {
                label: 'Generate a PGP Key Pair',
                cssClass: 'btn-primary',
                action: function(dialogItself)
				{
					$("#pgp_submit").click();
                }
            }]
        });
	$("#pgp_password").hidePassword(true);
	$('#generate_password').pGenerator({
		'bind': 'click',
		'passwordElement': '#password-input',
		'displayElement': '#display-password',
		'passwordLength': 16,
		'uppercase': true,
		'lowercase': true,
		'numbers':   true,
		'specialChars': false,
		'onPasswordGenerated': function(generatedPassword) 
		{
			$("#pgp_password").val(generatedPassword);
			$("#pgp_password").hideShowPassword(true);
		}
	});
}

function DecryptMessage()
{
    openpgp.init();
    var priv_key = openpgp.read_privateKey($('#pgp_private_key').val());
    var msg = openpgp.read_message($('#pgp_encrypted_message').val());
	var passphrase = $('#pgp_passphrase').val();
    
    var keymat = null;
	var sesskey = null;
	// Find the private (sub)key for the session key of the message
	for (var i = 0; i< msg[0].sessionKeys.length; i++) {
		if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
			keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
			sesskey = msg[0].sessionKeys[i];
			break;
		}
		for (var j = 0; j < priv_key[0].subKeys.length; j++) {
			if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
				keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
				sesskey = msg[0].sessionKeys[i];
				break;
			}
		}
	}
	if (keymat != null)
	{
		if (!keymat.keymaterial.decryptSecretMPIs(passphrase))
		{
			BootstrapDialog.show({
				type: BootstrapDialog.TYPE_WARNING,
				title: "Passphrase Error",
				message: '<label>Password for private key was incorrect !</label>',
				animate: false,
				buttons: [
				{
					label: 'Close',
					cssClass: 'btn-primary',
					action: function(dialog)
					{
						dialog.close();
					}
	            }]
			});
		}
		$('#pgp_encrypted_message').val(msg[0].decrypt(keymat, sesskey));
		Toggle2(true);
	}
	else
	{
		alert("No private key found!");
	}
}
