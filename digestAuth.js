// Author      : Charalampos Sykovaridis
// Title       : Digest Authentication library 

// Description : A simple custom library for nodeJS to compute the Authorization Header required for connecting with a 
// server using Digest Authentication . The library asks for username,password,url and a callback function to send background
// the options object for the connection.

// You can alter the User-Agent option as you wish

// Date  		: 18/8/2015
// Email 		: bampis.s@gmail.com


var crypto = require('crypto');
var http   = require('http');
var nc = "00000001";

var digest = function(username,password,url,method,sendBackData){
	this.username = username;
	this.password = password;
	this.url      = url;
	this.method   = method;

	//Call _getResponseHeader to get the first response from the server without Digest Authentication , after that a callback
	//function is called inorder to compute the HA1,HA2,cnonce and the response values
	this._getResponseHeader(this.url,this.username,this.password,method,function (response,_path,_host,username,_method,password,callback){
		var h1 = '';
		var h2 = '';

		if(response.algorithm == 'MD5' && response.qop == 'auth'){
			//console.log('Here we are');
			h1 = crypto.createHash('md5');
			h2 = crypto.createHash('md5');

			h1.update([username,response.realm,password].join(':'));
			h2.update([_method,_path].join(':'));

    		var cnonce = false;        
		    var cnonceHash = crypto.createHash('md5');

		    //Generate cnonce based on random math
		    cnonceHash.update(Math.random().toString(36));
		    cnonce = cnonceHash.digest('hex').substr(0, 8);
		    //------------------------------------

		     //Generate Response
		    var digestResponse = crypto.createHash('md5');
		    digestResponse.update(
		      						h1.digest('hex')+
							      	':'+
							      	response.nonce+
							      	':'+
							      	nc+
							      	':'+
							      	cnonce+
							      	':'+
							      	response.qop+
							      	':'+
							      	h2.digest('hex')
							      	);		      
		    //Response generated		      		  

		    //Initializing custom header with the User-Agent and the Authorization
   		  var header = {
   		  		"User-Agent": "Bampis Sykovaridis",
    		  	Authorization: 'Digest username="'+username+'",realm="'+response.realm+
			    '",nonce="'+response.nonce+'",uri="'+_path+'",qop="'+response.qop+'",response="'
			    +digestResponse.digest('hex')+'",opaque="'+response.opaque+'",nc="'+nc+'",cnonce="'+cnonce+'"'
			};
			//-----------------------------------------------------------------------


			//Setup the options object for connection
			var options = {
			  host: _host,
			  path: _path,
			  port: 80,
			  method: _method,
			  headers: header
			}
}//End of if
	//Send back to app.js the options object inorder to establish a connection
	return sendBackData(options);
});
}

digest.prototype._getResponseHeader = function getResponseHeaders(url,username,password,method,callback){

	var urlArray = url.split('/');
	var _host = urlArray[2];
	var _path = '';
	var digestResponseObject = {
		realm : '',
		nonce : '',
		opaque: '',
		algorithm : '',
		qop : ''
	};
	var realm,nonce,opaque,algorithm,qop;
	for(var i=3;i<urlArray.length;i++){
		_path += '/'+urlArray[i];
	}	
	var options = {method: 'HEAD', host: _host, port: 80, path: _path,headers: { "User-Agent": "Bampis Sykovaridis" }};
	var req = http.request(options, function(res) {
	    var result = JSON.stringify(res.headers);
	    var result_splitted = result.split(',');
	    realm = result_splitted[3];
	    nonce = result_splitted[5];
	    opaque = result_splitted[6];
	    algorithm = result_splitted[7];
	    qop = result_splitted[8];

	    realm = realm.split('\\');
	    realm[1] = realm[1].replace(/("|')/g, "");

	    nonce = nonce.split('\\');
	    nonce[1] = nonce[1].replace(/("|')/g, "");

		opaque = opaque.split('\\');
	    opaque[1] = opaque[1].replace(/("|')/g, "");

		algorithm = algorithm.split('\\');
	    algorithm[1] = algorithm[1].replace(/("|')/g, "");

		qop = qop.split('\\');
	    qop[1] = qop[1].replace(/("|')/g, "");

	    digestResponseObject.realm = realm[1];
	    digestResponseObject.nonce = nonce[1];
	    digestResponseObject.opaque = opaque[1];
	    digestResponseObject.algorithm = algorithm[1];
	    digestResponseObject.qop = qop[1];
	    
	    return callback(digestResponseObject,_path,_host,username,method,password);	    
	});
	req.end();
}

module.exports = {
	getDataWithAuth : function (username, password,url,method,callback) {
  			return new digest(username, password,url,method,callback);
	}
} 