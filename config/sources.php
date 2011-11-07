<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// userinput variables
	$V_USERINPUT = array(
		'$_GET',
		'$_POST',
		'$_COOKIE',
		'$_REQUEST',
		'$_FILES',
		'$_SERVER',
		'$_ENV',
		'$HTTP_GET_VARS',
		'$HTTP_POST_VARS',
		'$HTTP_COOKIE_VARS',  
		'$HTTP_REQUEST_VARS', 
		'$HTTP_POST_FILES',
		'$HTTP_SERVER_VARS',
		'$HTTP_ENV_VARS',
		'$HTTP_RAW_POST_DATA',
		'$argc',
		'$argv'
	);
	
	$V_SERVER_PARAMS = array(
		'HTTP_USER_AGENT',
		'HTTP_ACCEPT',
		'HTTP_ACCEPT_LANGUAGE',
		'HTTP_ACCEPT_ENCODING',
		'HTTP_ACCEPT_CHARSET',
		'HTTP_KEEP_ALIVE',
		'HTTP_CONNECTION',
		'QUERY_STRING',
		'REQUEST_URI', // partly urlencoded
		'PATH_INFO',
		'PATH_TRANSLATED',
		'PHP_SELF'
	);
	
	// file content as input
	$F_FILE_INPUT = array(
		'bzread',
		'dio_read',
		'fgets',
		'fgetss',
		'file', 
		'file_get_contents',
		'fread',
		'glob',
		'gzread',
		'readdir',
		'scandir',
		'zip_read'
	);
	
	// database content as input
	$F_DATABASE_INPUT = array(
		'mysql_fetch_array',
		'mysql_fetch_assoc',
		'mysql_fetch_field',
		'mysql_fetch_object',
		'mysql_fetch_row',
		'pg_fetch_all',
		'pg_fetch_array',
		'pg_fetch_assoc',
		'pg_fetch_object',
		'pg_fetch_result',
		'pg_fetch_row',
		'sqlite_fetch_all',
		'sqlite_fetch_array',
		'sqlite_fetch_object',
		'sqlite_fetch_single',
		'sqlite_fetch_string'
	);
	
	// other functions as input
	$F_OTHER_INPUT = array(
		'get_headers',
		'getFormData'
	);
	
	//	'getenv' and 'apache_getenv' 
	// will be automatically added if 'putenv' or 'apache_setenv' with userinput is found
	
