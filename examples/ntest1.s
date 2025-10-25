# Taylor series implementation using RISC-V F extension (Lab - 3)

.data

.word 5,1, 0x3f800000, 5, 0, 0x40000000, 8,2,0x40000000,3,3,0x40200000,3,4,0x3fc00000,10




.text

#The following line initializes register x3 with 0x10000000


#so that you can use x3 for referencing various memory locations.

lui x3, 0x10000
addi sp , sp , -8



main_program:


	addi sp ,sp , -16

	sd x1 , 0(sp)

	sd x8 , 8(sp)

	# now we have set up stack frame to restore values

        # temp variable for iteration over inputs
        addi x8 , x3 , 0
        lw x29 , 0(x8)
        addi x9 , x8 , 4
        

	# N = number of inputs

	# storage base address is x9

	lui x10 , 0x10000

	addi x10 , x10 , 0x200

	

	

	add x4 , x0 , x0 # Loop counter (so that we can stop at N inputs)

	

	

start_main_loop:



	bge x4 , x29 , loop_end
	
	lw x12 , 0(x9)
	flw f10 , 4(x9)
	lw x11 , 8(x9)

	# loaded fucntion code  , x , number of terms
	

	bge x0 , x11 , invalid_input
	

	# check each function code and apply that fucntion accordingly

	

	addi x13 , x0 , 0

	beq x12 , x13 , call_exp

	

	addi x13 , x0 , 1

	beq x12 , x13 , call_sin

	
	addi x13 , x0 , 2

	beq x12 , x13 , call_cos

	
	addi x13 , x0 , 3

	beq x12 , x13 , call_ln

	

	addi x13 , x0 , 4

	beq x12 , x13 , call_reciprocal

	

	# handles inavlid function code

	jal x0 , invalid_input

	



    

call_exp:



	jal x1 , e_x

	jal x0 , store_result_and_continue

	

	

call_sin:



	jal x1 , sin_x

	jal x0 , store_result_and_continue

	

call_cos:



	jal x1, cos_x

	jal x0 , store_result_and_continue

	

call_ln:



	jal x1, ln_x

	jal x0 , store_result_and_continue

	

call_reciprocal:



	jal x1 , reciprocal_x

	jal x0 , store_result_and_continue

	

	

invalid_input:

# load NaN value into x5 register and move it to x10 register



	addi x31 , x0 , 0
	fcvt.s.w f31 , x31
	fdiv.s f10 , f31 , f31





store_result_and_continue:



	

       fsw f10 , 0(x10)

	# after storing increment all pointer variables and the loop counter variavble

	addi x9 , x9 , 12

	addi x10 , x10 , 4

	addi x4 , x4 ,1

	

	

	jal x0 , start_main_loop

	



	




# function code 0 : e^x 





e_x:

	addi sp , sp , -16

	sd x1 , 0(sp) # saves return address

	sd x10 , 8(sp)



	addi x31,x0,1
	fcvt.s.w f11,x31 # f11 = 1.0f
	
	addi x31,x0,0
	fcvt.s.w f12,x31 #f12 = 0.0f
	

	fadd.s f12 , f12 , f11 #f12 = 1.0
	fmv.s f13 , f11 # f13 = 1.0
	
	addi x30 , x0 , 1 # i = 1
	

e_x_loop:



	bge x30 , x11 , e_x_end

	fcvt.s.w f14 , x30
	fmul.s f13 , f13 , f10
	fdiv.s f13 , f13 , f14 
	fadd.s f12 , f12 , f13
	
	
	addi x30 , x30 , 1
	jal x0 , e_x_loop
	

	# calculate the following term of x^n /n!



	

e_x_end:



	fmv.s f10 , f12
	ld x1 , 0(sp)
	ld x10 , 8(sp)
	
	addi sp , sp , 16
	jalr x0 , 0(x1)
	



# Function code 1: sin(x)



sin_x:


	addi sp , sp , -16
	
	sd x1 , 0(sp)
	sd x10 , 8(sp)
	
	fmv.s f0 , f10
	
	addi x31,x0,0
	fcvt.s.w f11,x31
	
	fmv.s f12 , f10
	
	addi x5 , x0 , 0

	

sin_x_loop:



	bge x5 , x11 , sin_x_end

    	andi x12, x5, 1

    	beq  x12, x0, sin_x_add_term

	

sin_x_subtract_term:



	# in taylor series some of the terms need to be subtracted so this takes care of those terms

	fsub.s f11 , f11,f12
	jal x0 , sin_x_loop_continued
	
sin_x_add_term:

	fadd.s f11 , f11 , f12

	

sin_x_loop_continued:

	
	fmul.s f12 , f12 , f0
	fmul.s f12 , f12 , f0
	
	slli x12 , x5 , 1
	addi x13 , x12 , 2
	addi x14 , x12 , 3
	
	fcvt.s.w f13 , x13
	fcvt.s.w f14 , x14
	
	fdiv.s f12 , f12, f13
	
	
	fdiv.s f12 , f12 , f14
	
	addi x5 , x5 , 1
	jal x0 , sin_x_loop

sin_x_end:
	fcvt.s.w f0, x0

	fadd.s f10,f11,f0
	
	ld x1 , 0(sp)
	ld x10 , 8(sp)
	
	addi sp , sp , 16
	jalr x0 , 0(x1)
	

	

# function code 2 : cos(x)



cos_x:



	addi sp , sp , -16
	
	
	sd x1 , 0(sp)
	sd x10 , 8(sp)
	
	addi x31,x0,1
	fcvt.s.w f11,x31
	addi x31,x0,1
	fcvt.s.w f12,x31
	
	addi x5 , x0 , 1

	

cos_x_loop:



	bge x5 , x11, cos_x_end

	
	fmul.s f12 , f12 , f10
	
	fmul.s f12 , f12 , f10
	
	
	
	slli x12 , x5 , 1
	
	
	addi x13 , x12 , -1
	
	
	
	fcvt.s.w f13 , x12
	
	fcvt.s.w f14 , x13
	
	fdiv.s f12 , f12 , f13
	
	fdiv.s f12 , f12 , f14
	
	
	andi x12 , x5 , 1
	bne x12 , x0 , cos_x_subtract_term
	
cos_x_add_term:

	fadd.s f11 , f11 , f12
	jal x0 , cos_x_loop_continued	
	

cos_x_subtract_term:

	fsub.s f11 , f11 , f12
	

cos_x_loop_continued:



	addi x5 , x5 , 1

	jal x0 , cos_x_loop

	

cos_x_end:


	fmv.s f10 , f11
	ld x1 , 0(sp)
	ld x10 , 8(sp)
	
	addi sp , sp , 16
	jalr x0 , 0(x1)

	



# Function code 3 : ln(x)



ln_x:

	addi sp , sp , -16

	sd x1 , 0(sp)
	sd x10 , 8(sp)
	
	addi x31,x0,0
	fcvt.s.w f11,x31 
	
	fle.s x31 , f10 , f11
	bne x31 , x0 , invalid_input_for_ln
	
	# f11 = 0.0
	
	
	#flt.s x31 , f10 , f11
	#fcvt.s.w f12 , x31
	
	
	#fmv.x.s x12 , f12
	
	
	#bne x31 , x0 , invalid_input_for_ln
	
	addi x31 , x0 , 1
	fcvt.s.w f11 , x31
	fadd.s f11 , f11 , f11
	fle.s x31 , f11 , f10
	bne x31 , x0 , invalid_input_for_ln
	
	
    	flt.s x31, f10, f11

    	bne   x31, x0, invalid_input_for_ln

	
	addi x31,x0,1
	fcvt.s.w f11,x31
	fsub.s f12 , f10 , f11
	addi x31,x0,0
	fcvt.s.w f13,x31
	
	fmv.s f14 , f12
	
	addi x5 , x0 , 1
	
	

	

ln_x_loop:



	bge x5 , x11 , ln_x_end

	fcvt.s.w f15 , x5
	
	fdiv.s f16 , f14 , f15
	addi x12 , x5 , -1
	andi x12 , x12 , 1
	
	bne x12 , x0 , ln_x_subtract_term

ln_add:

    	fadd.s f13, f13, f16
    	jal x0, ln_x_loop_continued

ln_x_subtract_term:

	

	fsub.s f13 , f13 , f16

	

ln_x_loop_continued:


	fmul.s f14 , f14 , f12
	addi x5 , x5 , 1
	
	jal x0 , ln_x_loop

	


	

ln_x_end:


	fmv.s f10 , f13
	ld x1 , 0(sp)
	ld x10, 8(sp)
	
	addi sp , sp , 16
	jalr x0 , 0(x1)
	
	

invalid_input_for_ln:



	# return NaN
	addi x31,x0,0
	fcvt.s.w f31,x31
	fdiv.s f10,f31,f31
	
	ld x1, 0(sp)
	ld x10, 8(sp)
	
	addi sp , sp , 16
	jalr x0 , 0(x1)
	

# Function code 4 : 1/x



reciprocal_x:







	addi sp , sp , -16
	
	
	
	sd x1 , 0(sp)
	
	sd x10 , 8(sp)
	
	
	
	
	addi x31,x0,0
	
	fcvt.s.w f11,x31
	
	
	
	fle.s x31, f10, f11
	
	
	
	bne x31, x0, invalid_input_reciprocal
	
	
	
	addi x31 , x0 , 1
	
	fcvt.s.w f11 , x31
	
	fadd.s f11 , f11 , f11
	
	fle.s x31 , f11 , f10
	
	bne x31 , x0 , invalid_input_reciprocal
	
	
	
	
	addi x31,x0,1
	
	fcvt.s.w f11,x31
	
	
	fsub.s f12 , f10, f11
	
	fmv.s f13 , f11
	
	fmv.s f14 , f11
	
	addi x5 , x0 , 1
	



reciprocal_loop:


	
	bge x5 , x11 , reciprocal_end
	
	fmul.s f14 , f14 , f12
	
	andi x12 , x5, 1
	
	bne x12 , x0 , reciprocal_subtract_term
	
	
reciprocal_add_term:


	
	fadd.s f13 , f13 , f14
	
	jal x0 , reciprocal_loop_continued
	


reciprocal_subtract_term:



	fsub.s f13 , f13 , f14


reciprocal_loop_continued:

	
	addi x5 , x5 , 1
	
	jal x0 , reciprocal_loop
	



reciprocal_end:



	fmv.s f10 , f13
	
	ld x1 , 0(sp)
	
	ld x10 , 8(sp)
	
	addi sp , sp , 16
	
	jalr x0 , 0(x1)
	




invalid_input_reciprocal:






	
	# return NaN
	
	
	
	addi x31,x0,0
	
	fcvt.s.w f31,x31
	
	fdiv.s f10,f31,f31
	
	ld x1 , 0(sp)
	
	ld x10 , 8(sp)
	
	addi sp , sp , 16
	
	jalr x0 , 0(x1)
	
loop_end:



	

	# now restore stack frame so that values are restored

	ld x1 , 0(sp)

	ld x8 , 8(sp)

	addi sp , sp , 16

	# jalr x0 ,0(x1)

	

	

		

	

	

	

	



#your code starts here



#The final result should be in memory starting from address 0x10000200 #The first word location at 0x10000200 contains the Taylor Series approximation of func1(func1_x) up to func1_terms in FP32 format.



#The second word location from 0x10000200 contains the Taylor Series approximation of func2(func2_x) up to func2_terms in FP32 format.



# and so on.