<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
Copyright (C) 2010 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.

**/
	
	// delete all tokens to ignore while scanning, mostly whitespaces	
	function prepare_tokens($tokens, $T_IGNORE)
	{	
		// delete whitespaces and other unimportant tokens
		for($i=0, $c=count($tokens); $i<$c; $i++)
		{
			if( is_array($tokens[$i]) ) 
			{
				if( in_array($tokens[$i][0], $T_IGNORE) )
					unset($tokens[$i]);
				else if( $tokens[$i][0] === T_CLOSE_TAG )
					$tokens[$i] = ';';	
				else if( $tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING )
					$tokens[$i][1] = str_replace('"', "'", $tokens[$i][1]);
			}
		}
		
		// return tokens with rearranged key index
		return array_values($tokens);
	}	
	
	// adds braces around offsets
	function wrapbraces($tokens, $start, $between, $end)
	{
		$tokens = array_merge(
			array_slice($tokens, 0, $start), array('{'), 
			array_slice($tokens, $start, $between), array('}'),
			array_slice($tokens, $end)
		);	
		return $tokens;
	}
		
	// some tokenchains need to be fixed to scan correctly later	
	function fix_tokens($tokens)
	{	
		for($i=0; $i<count($tokens); $i++)
		{
		// convert `backticks` to backticks()
			if( $tokens[$i] === '`' )
			{		
				$f=1;
				while( $tokens[$i+$f] !== '`' && $tokens[$i+$f] !== ';' )
				{		
					// get line_nr of any near token
					if( is_array($tokens[$i+$f]) )
						$line_nr = $tokens[$i+$f][2];
						
					if($f>50)break;
					
					$f++;
				}
				if(!empty($line_nr))
				{ 
					$tokens[$i+$f] = ')';
					$tokens[$i] = array(T_STRING, 'backticks', $line_nr);
				
					// add element backticks() to array 			
					$tokens = array_merge(
						array_slice($tokens, 0, $i+1), array('('), 
						array_slice($tokens, $i+1)
					);	
				}

			}
		// rewrite $array{index} to $array[index]
			else if( $tokens[$i] === '{'
			&& ((is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_VARIABLE)
			|| $tokens[$i-1] === ']') )
			{
				$tokens[$i] = '[';
				$f=1;
				while($tokens[$i+$f] !== '}')
				{
					$f++;
				}
				$tokens[$i+$f] = ']';
			}
		// handle ternary operator (remove condition, only values should be handled during trace)
		// problem: tainting in the condition is not actual tainting the line -> remove condition
			else if( $tokens[$i] === '?' )
			{
				$tokens[$i] = '';
				// condition in brackets: fine, delete condition
				if($tokens[$i-1] === ')')
				{
					$tokens[$i-1] = '';
					// delete tokens till ( 
					$newbraceopen = 1;
					$f = 2;
					while( !($newbraceopen === 0 || $tokens[$i - $f] === ';') )
					{
						if( $tokens[$i - $f] === '(' )
						{
							$newbraceopen--;
						}
						else if( $tokens[$i - $f] === ')' )
						{
							$newbraceopen++;
						}
						$tokens[$i - $f] = '';	
						if($f>50)break;
						$f++;
					}

					//delete token before, if T_STRING
					if(is_array($tokens[$i-$f]) 
					&& ($tokens[$i-$f][0] === T_STRING || $tokens[$i-$f][0] === T_EMPTY || $tokens[$i-$f][0] === T_ISSET))
					{
						$tokens[$i-$f] = '';
					}
				}
				// condition is a check or assignment
				else if(in_array($tokens[$i-2][0], $GLOBALS['T_ASSIGNMENT']) || in_array($tokens[$i-2][0], $GLOBALS['T_OPERATOR']) )
				{
					// remove both operands
					$tokens[$i-1] = '';
					$tokens[$i-2] = '';
					// if operand is in braces
					if($tokens[$i-3] === ')')
					{
						// delete tokens till ( 
						$newbraceopen = 1;
						$f = 4;
						while( !($newbraceopen === 0 || $tokens[$i - $f] === ';') )
						{
							if( $tokens[$i - $f] === '(' )
							{
								$newbraceopen--;
							}
							else if( $tokens[$i - $f] === ')' )
							{
								$newbraceopen++;
							}
						
							$tokens[$i - $f] = '';	
							if($f>50)break;
							$f++;
						}

						//delete token before, if T_STRING
						if(is_array($tokens[$i-$f]) 
						&& ($tokens[$i-$f][0] === T_STRING || $tokens[$i-$f][0] === T_EMPTY || $tokens[$i-$f][0] === T_ISSET))
						{
							$tokens[$i-$f] = '';
						}
					}
					// if first operand is an $array['key']
					else if($tokens[$i-3] === ']' && $tokens[$i-4][0] === T_CONSTANT_ENCAPSED_STRING && $tokens[$i-5] === '[')
					{
						$tokens[$i-4] = ''; // 'key'
						$tokens[$i-5] = ''; // [
						$tokens[$i-6] = ''; // $array
					}
					$tokens[$i-3] = '';
					
				}
				// condition is a single variable, delete
				else if(is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_VARIABLE)
				{
					$tokens[$i-1] = '';
				}
				// condition is a single array key, delete
				else if($tokens[$i-1] === ']' && $tokens[$i-2][0] === T_CONSTANT_ENCAPSED_STRING && $tokens[$i-3] === '[')
				{
					$tokens[$i-1] = ''; // ]
					$tokens[$i-2] = ''; // 'key'
					$tokens[$i-3] = ''; // [
					$tokens[$i-4] = ''; // $array
				}
			}
		// real token
			else if( is_array($tokens[$i]) )
			{
			// rebuild if-clauses without { }
				if ($tokens[$i][0] === T_IF || $tokens[$i][0] === T_ELSEIF )
				{				
					$f=4; $start=$end=0;
					while( $tokens[$i+$f] !== '{' )
					{		
						// idea: if there is a var or functioncall with a ')' infront 
						// it must be a if() without { }
						if( is_array($tokens[$i+$f])
						&& $tokens[$i+$f-1] === ')' 
						&& ($tokens[$i+$f][0] === T_VARIABLE
						|| in_array($tokens[$i+$f][0], $GLOBALS['T_FUNCTIONS']) ) )
							$start = $i+$f;
							
						if ( $tokens[$i+$f] === ';' )
						{
							$end = $i+$f; break;
						}
						
						if($f>50)break;
							
						$f++;
					}
					
					if($start && $end)
					{ 
						$tokens = wrapbraces($tokens, $start, $end-$start+1, $end+1);
						$i = $start;
					}		
				} 
			// rebuild else without { }	
				else if( $tokens[$i][0] === T_ELSE 
				&& $tokens[$i+1][0] !== T_IF
				&& $tokens[$i+1] !== '{')
				{	
					$f=2;
					while( $tokens[$i+$f] !== ';' )
					{		
						if($f>50)break;
						$f++;
					}
					$tokens = wrapbraces($tokens, $i+1, $f, $i+$f+1);
				}
			// rebuild switch case: without { }	
				else if( $tokens[$i][0] === T_CASE
				&& $tokens[$i+2] === ':'
				&& $tokens[$i+3] !== '{' )
				{
					$f=3;
					while( isset($tokens[$i+$f]) 
					&& !(is_array($tokens[$i+$f]) && $tokens[$i+$f][0] === T_BREAK ) )
					{		
						if($f>250)break;
						$f++;
					}
					$tokens = wrapbraces($tokens, $i+3, $f-1, $i+$f+2);
					$i++;
				}
			// rebuild switch default: without { }	
				else if( $tokens[$i][0] === T_DEFAULT
				&& $tokens[$i+2] !== '{' )
				{
					$f=2;
					while( $tokens[$i+$f] !== ';' )
					{		
						if($f>250)break;
						$f++;
					}
					$tokens = wrapbraces($tokens, $i+2, $f-1, $i+$f+1);
				}
			// lowercase all function names because PHP doesn't care	
				else if( $tokens[$i][0] === T_FUNCTION )
				{
					$tokens[$i+1][1] = strtolower($tokens[$i+1][1]);
				}	
				else if( $tokens[$i][0] === T_STRING )
				{
					$tokens[$i][1] = strtolower($tokens[$i][1]);
				}	
			}	
		}
		// return tokens with rearranged key index
		return array_values($tokens);
	}

