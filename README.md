SlowlorisChecker
================

This is a simple script to check if some server could be affected by Slowloris attack (Not executing the attack itself)

=======================

 Ya que el script de slowloris de nmap no funciona                            
 he dedidido hacer la misma prueba de una forma ad hoc pero se basa en la     
 misma mecánica:                                                              
                                                                              
 Abrimos dos conexiones al mismo tiempo al servidor:                          
 1 - Conexión de control: Esta conexión no enviará nada a parte de un par de  
 cabeceras y esperará a que de timeout el servidor.                           
 2 - Conexión de retraso: Esta conexión se crea a la misma vez que la primera,
     envia las mismas cabeceras, espera 10 segundos y envia una cabecera más  
     al servidor. Espera a que de timeout el servidor.                        
                                                                              
 Si hay una diferencia de tiempos entre el timeout 1 y el 2 de 10 segundos o  
 más, entonces podemos concluir que el servidor es vulnerable a este ataque,  
 ya que una conexión podrá mantenerse ocupada en el servidor mientras se      
 envien cabeceras cada 10 segundos (tiempo configurable).                     

Explicación completa del método utilizado tomada del enlace siguiente: 
 
https://community.qualys.com/blogs/securitylabs/2011/07/07/identifying-slow-http-attack-vulnerabilities-on-web-applications
