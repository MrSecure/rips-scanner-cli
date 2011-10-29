<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
	
	// cross-site scripting affected functions
	// parameter = 0 means, all parameters will be traced
	$NAME_XSS = 'Cross-Site Scripting';
	$F_XSS = array(
		'echo'							=> array(array(1), $F_SECURING_XSS), 
		'print'							=> array(array(1), $F_SECURING_XSS),
		'printf'						=> array(array(0), $F_SECURING_XSS),
		'vprintf'						=> array(array(0), $F_SECURING_XSS)
	);
	
	// code evaluating functions  => (parameters to scan, securing functions)
	// example parameter array(1,3) will trace only first and third parameter 
	$NAME_CODE = 'Code Evaluation';
	$F_CODE = array(
		'array_filter'					=> array(array(2), array()),
		'array_map'						=> array(array(1), array()),
		'array_walk'					=> array(array(2), array()),
		'array_walk_recursive'			=> array(array(2), array()),
		'assert' 						=> array(array(1), array()),
//		'call_user_func'				=> array(array(1), array()),
//		'call_user_func_array'			=> array(array(1), array()),
		'create_function' 				=> array(array(1,2), array()),
		'eval' 							=> array(array(1), array()),
		'iterator_apply'				=> array(array(2), array()),
		'mb_ereg_replace'				=> array(array(1,2), $F_SECURING_PREG),
		'mb_eregi_replace'				=> array(array(1,2), $F_SECURING_PREG),
		'preg_replace'					=> array(array(1,2), $F_SECURING_PREG),
		'preg_replace_callback'			=> array(array(1,2), $F_SECURING_PREG),
		'register_shutdown_function'	=> array(array(1), array()),
		'register_tick_function'		=> array(array(1), array()),
		'usort'							=> array(array(2), array())	
	);
	
	// file inclusion functions => (parameters to scan, securing functions)
	$NAME_FILE_INCLUDE = 'File Inclusion';
	$F_FILE_INCLUDE = array(
		'include' 						=> array(array(1), $F_SECURING_FILE),
		'include_once' 					=> array(array(1), $F_SECURING_FILE),
		'php_check_syntax' 				=> array(array(1), $F_SECURING_FILE),	
		'require' 						=> array(array(1), $F_SECURING_FILE),
		'require_once' 					=> array(array(1), $F_SECURING_FILE),
		'set_include_path' 				=> array(array(1), $F_SECURING_FILE),
		'virtual' 						=> array(array(1), $F_SECURING_FILE)		
	);

	// file affecting functions  => (parameters to scan, securing functions)
	// file handler functions like fopen() are added as parameter 
	// for functions that use them like fread() and fwrite()
	$NAME_FILE_READ = 'File Disclosure';
	$F_FILE_READ = array(
		'bzread'						=> array(array(1), $F_SECURING_FILE), 
		'bzflush'						=> array(array(1), $F_SECURING_FILE), 
		'dio_read'						=> array(array(1), $F_SECURING_FILE),   
		'fdf_open'						=> array(array(1), $F_SECURING_FILE), 
		'file'							=> array(array(1), $F_SECURING_FILE), 
		'file_get_contents'				=> array(array(1), $F_SECURING_FILE),  
		'finfo_file'					=> array(array(1,2), array()), 
		'fflush'						=> array(array(1), $F_SECURING_FILE),
		'fgetc'							=> array(array(1), $F_SECURING_FILE),
		'fgetcsv'						=> array(array(1), $F_SECURING_FILE),
		'fgets'							=> array(array(1), $F_SECURING_FILE),
		'fgetss'						=> array(array(1), $F_SECURING_FILE),
		'fread'							=> array(array(1), $F_SECURING_FILE), 
		'fpassthru'						=> array(array(1,2), array()), 
		'fscanf'						=> array(array(1), $F_SECURING_FILE), 
		'glob'							=> array(array(1), array()), 
		'gzfile'						=> array(array(1), $F_SECURING_FILE), 
		'gzgetc'						=> array(array(1), $F_SECURING_FILE),
		'gzgets'						=> array(array(1), $F_SECURING_FILE), 
		'gzgetss'						=> array(array(1), $F_SECURING_FILE), 
		'gzread'						=> array(array(1), $F_SECURING_FILE),  
		'gzpassthru'					=> array(array(1), $F_SECURING_FILE), 
		'highlight_file'				=> array(array(1), $F_SECURING_FILE),  
		'imagecreatefrompng'			=> array(array(1), $F_SECURING_FILE), 
		'imagecreatefromjpg'			=> array(array(1), $F_SECURING_FILE), 
		'imagecreatefromgif'			=> array(array(1), $F_SECURING_FILE), 
		'imagecreatefromgd2'			=> array(array(1), $F_SECURING_FILE), 
		'imagecreatefromgd2part'		=> array(array(1), $F_SECURING_FILE), 
		'imagecreatefromgd'				=> array(array(1), $F_SECURING_FILE),  
		'opendir'						=> array(array(1), $F_SECURING_FILE),  
		'parse_ini_file' 				=> array(array(1), $F_SECURING_FILE),	
		'readfile'						=> array(array(1), $F_SECURING_FILE), 
		'readgzfile'					=> array(array(1), $F_SECURING_FILE), 
		'readlink'						=> array(array(1), $F_SECURING_FILE),		
		//'stat'						=> array(array(1), array()),
		'scandir'						=> array(array(1), $F_SECURING_FILE),
		'show_source'					=> array(array(1), $F_SECURING_FILE),
		'zip_open'						=> array(array(1), $F_SECURING_FILE)
	);
	
	// file or file system affecting functions
	$NAME_FILE_AFFECT = 'File Manipulation';
	$F_FILE_AFFECT = array(
		'bzwrite'						=> array(array(2), array()),
		'chmod'							=> array(array(1), $F_SECURING_FILE),
		'chgrp'							=> array(array(1), $F_SECURING_FILE),
		'chown'							=> array(array(1), $F_SECURING_FILE),
		'copy'							=> array(array(1), array()),
		'dio_write'						=> array(array(2), array()),		
		'file_put_contents'				=> array(array(1,2), $F_SECURING_FILE),
		'fputcsv'						=> array(array(1,2), $F_SECURING_FILE),
		'fputs'							=> array(array(1,2), $F_SECURING_FILE),	
		'ftruncate'						=> array(array(1), $F_SECURING_FILE),
		'fwrite'						=> array(array(1,2), $F_SECURING_FILE),		
		'gzwrite'						=> array(array(1,2), array()),
		'gzputs'						=> array(array(1,2), array()),
		'mkdir'							=> array(array(1), array()),
		'move_uploaded_file'			=> array(array(1), $F_SECURING_FILE),	
		'recode_file'					=> array(array(2,3), $F_SECURING_FILE),	
		'rename'						=> array(array(1,2), $F_SECURING_FILE),
		'rmdir'							=> array(array(1), $F_SECURING_FILE),	
		'touch'							=> array(array(1), $F_SECURING_FILE),
		'unlink'						=> array(array(1), $F_SECURING_FILE)		
	);

	// OS Command executing functions => (parameters to scan, securing functions)
	$NAME_EXEC = 'Command Execution';
	$F_EXEC = array(
		'backticks'						=> array(array(1), $F_SECURING_SYSTEM),
		'exec'							=> array(array(1), $F_SECURING_SYSTEM),
		'passthru'						=> array(array(1), $F_SECURING_SYSTEM),
		'pcntl_exec'					=> array(array(1), $F_SECURING_SYSTEM),
		'popen'							=> array(array(1), $F_SECURING_SYSTEM),
		'proc_open'						=> array(array(1), $F_SECURING_SYSTEM),
		'shell_exec'					=> array(array(1), $F_SECURING_SYSTEM),
		'system'						=> array(array(1), $F_SECURING_SYSTEM)
	);

	// SQL executing functions => (parameters to scan, securing functions)
	$NAME_DATABASE = 'SQL Injection';
	$F_DATABASE = array(
	// Abstraction Layers
		'dba_open'						=> array(array(1), array()),
		'dba_popen'						=> array(array(1), array()), 
		'dba_insert'					=> array(array(1,2), array()),
		'dba_fetch'						=> array(array(1), array()), 
		'dba_delete'					=> array(array(1), array()), 
		'dbx_query'						=> array(array(2), $F_SECURING_SQL), 
		'odbc_do'						=> array(array(2), $F_SECURING_SQL),
		'odbc_exec'						=> array(array(2), $F_SECURING_SQL),
		'odbc_execute'					=> array(array(2), $F_SECURING_SQL),
	// Vendor Specific	
		'db2_exec' 						=> array(array(2), $F_SECURING_SQL),
		'db2_execute'					=> array(array(2), $F_SECURING_SQL),
		'fbsql_db_query'				=> array(array(2), $F_SECURING_SQL),
		'fbsql_query'					=> array(array(1), $F_SECURING_SQL), 
		'ibase_query'					=> array(array(2), $F_SECURING_SQL), 
		'ibase_execute'					=> array(array(1), $F_SECURING_SQL), 
		'ifx_query'						=> array(array(1), $F_SECURING_SQL), 
		'ifx_do'						=> array(array(1), $F_SECURING_SQL),
		'ingres_query'					=> array(array(2), $F_SECURING_SQL),
		'ingres_execute'				=> array(array(2), $F_SECURING_SQL),
		'ingres_unbuffered_query'		=> array(array(2), $F_SECURING_SQL),
		'msql_db_query'					=> array(array(2), $F_SECURING_SQL), 
		'msql_query'					=> array(array(1), $F_SECURING_SQL),
		'msql'							=> array(array(2), $F_SECURING_SQL), 
		'mssql_query'					=> array(array(1), $F_SECURING_SQL), 
		'mssql_execute'					=> array(array(1), $F_SECURING_SQL),
		'mysql_db_query'				=> array(array(2), $F_SECURING_SQL),  
		'mysql_query'					=> array(array(1), $F_SECURING_SQL), 
		'mysql_unbuffered_query'		=> array(array(1), $F_SECURING_SQL), 
		'mysqli_stmt_execute'			=> array(array(1), $F_SECURING_SQL),
		'mysqli_query'					=> array(array(2), $F_SECURING_SQL),
		'mysqli_real_query'				=> array(array(1), $F_SECURING_SQL),
		'mysqli_master_query'			=> array(array(2), $F_SECURING_SQL),
		'oci_execute'					=> array(array(1), array()),
		'ociexecute'					=> array(array(1), array()),
		'ovrimos_exec'					=> array(array(2), $F_SECURING_SQL),
		'ovrimos_execute'				=> array(array(2), $F_SECURING_SQL),
		'ora_do'						=> array(array(2), array()), 
		'ora_exec'						=> array(array(1), array()), 
		'pg_query'						=> array(array(2), $F_SECURING_SQL),
		'pg_send_query'					=> array(array(2), $F_SECURING_SQL),
		'pg_send_query_params'			=> array(array(2), $F_SECURING_SQL),
		'pg_send_prepare'				=> array(array(3), $F_SECURING_SQL),
		'pg_prepare'					=> array(array(3), $F_SECURING_SQL),
		'sqlite_open'					=> array(array(1), $F_SECURING_SQL),
		'sqlite_popen'					=> array(array(1), $F_SECURING_SQL),
		'sqlite_array_query'			=> array(array(1,2), $F_SECURING_SQL),
		'arrayQuery'					=> array(array(1,2), $F_SECURING_SQL),
		'singleQuery'					=> array(array(1), $F_SECURING_SQL),
		'sqlite_query'					=> array(array(1,2), $F_SECURING_SQL),
		'sqlite_exec'					=> array(array(1,2), $F_SECURING_SQL),
		'sqlite_single_query'			=> array(array(2), $F_SECURING_SQL),
		'sqlite_unbuffered_query'		=> array(array(1,2), $F_SECURING_SQL),
		'sybase_query'					=> array(array(1), $F_SECURING_SQL), 
		'sybase_unbuffered_query'		=> array(array(1), $F_SECURING_SQL)
	);
	
	// xpath injection
	$NAME_XPATH = 'XPath Injection';
	$F_XPATH = array(
		'xpath_eval'					=> array(array(2), $F_SECURING_XPATH),	
		'xpath_eval_expression'			=> array(array(2), $F_SECURING_XPATH),		
		'xptr_eval'						=> array(array(2), $F_SECURING_XPATH)
	);
	
	// ldap injection
	$NAME_LDAP = 'LDAP Injection';
	$F_LDAP = array(
		'ldap_add'						=> array(array(2,3), $F_SECURING_LDAP),
		'ldap_delete'					=> array(array(2), $F_SECURING_LDAP),
		'ldap_list'						=> array(array(3), $F_SECURING_LDAP),
		'ldap_read'						=> array(array(3), $F_SECURING_LDAP),
		'ldap_search'					=> array(array(3), $F_SECURING_LDAP)
	);	
		
	// connection handling functions
	$NAME_CONNECT = 'Header Injection';
    $F_CONNECT = array(
		'curl_setopt'					=> array(array(2,3), array()),
		'curl_setopt_array' 			=> array(array(2), array()),
		'cyrus_query' 					=> array(array(2), array()),
		'error_log'						=> array(array(3), array()),
		'fsockopen'						=> array(array(1), array()), 
		'ftp_chmod' 					=> array(array(2,3), array()),
		'ftp_exec'						=> array(array(2), array()), 
		'ftp_delete' 					=> array(array(2), array()), 
		'ftp_fget' 						=> array(array(3), array()), 
		'ftp_get'						=> array(array(2,3), array()), 
		'ftp_nlist' 					=> array(array(2), array()), 
		'ftp_nb_fget' 					=> array(array(3), array()), 
		'ftp_nb_get' 					=> array(array(2,3), array()), 
		'header' 						=> array(array(1), array()),
		'imap_open'						=> array(array(1), array()),  
		'imap_mail'						=> array(array(1), array()),
		'mail' 							=> array(array(1,4), array()), 
		'pfsockopen'					=> array(array(1), array()),   
		'session_register'				=> array(array(0), array()),  
		'socket_bind'					=> array(array(2), array()),  
		'socket_connect'				=> array(array(2), array()),  
		'socket_send'					=> array(array(2), array()), 
		'socket_write'					=> array(array(2), array()),  
		'stream_socket_client'			=> array(array(1), array()),  
		'stream_socket_server'			=> array(array(1), array())
	);
	
	// other critical functions
	$NAME_OTHER = 'Possible Flow Control'; // :X
	$F_OTHER = array(
		'apache_setenv'					=> array(array(1,2), array()),	
		'dl' 							=> array(array(1), array()),	
		'ereg'							=> array(array(2), array()), # nullbyte injection affected		
		'eregi'							=> array(array(2), array()), # nullbyte injection affected	
		'extract'						=> array(array(1), array()),
		'import_request_variables'		=> array(array(1), array()),		
		'ini_set' 						=> array(array(1,2), array()),
		'putenv'						=> array(array(1), array()),
		'sleep'							=> array(array(1), array()),
		'unserialize'					=> array(array(1), array())
	);
	
	// property oriented programming with unserialize
	$NAME_POP = 'Unserialize';
	$F_POP = array(
		'unserialize'					=> array(array(1), array())
	);

