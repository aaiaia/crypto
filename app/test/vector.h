#ifndef VECTOR_H
#define VECTOR_H
/****************************************************************************************************/
const uint32_t TV_u32_add_ref_0[] = {
    0x00000000ul, 0x00000000ul, 0x00000000ul, 0x00000001ul,
};
const uint32_t TV_u32_add_opA_0[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFEul, 0x00000000ul,
};
const uint32_t TV_u32_add_opB_0[] = {
    0x00000001ul, 0x00000000ul, 0x00000001ul, 0x00000000ul,
};
const uint32_t TV_u32_add_carry_0 = 0x00000000;

const uint32_t TV_u32_add_ref_1[] = {
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000001ul,
};
const uint32_t TV_u32_add_opA_1[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
};
const uint32_t TV_u32_add_opB_1[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
};
const uint32_t TV_u32_add_carry_1 = 0x00000000;

const uint32_t TV_u32_add_ref_2[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000001ul,
};
const uint32_t TV_u32_add_opA_2[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
};
const uint32_t TV_u32_add_opB_2[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
};
const uint32_t TV_u32_add_carry_2 = 0x00000001;

#define TV_U32_ADD_NUM  3u
const size_t TV_u32_add_lenList[] = {
    sizeof(TV_u32_add_ref_0),
    sizeof(TV_u32_add_ref_1),
    sizeof(TV_u32_add_ref_2),
};
const uint32_t* TV_u32_add_refList[] = {
    TV_u32_add_ref_0,
    TV_u32_add_ref_1,
    TV_u32_add_ref_2,
};
const uint32_t* TV_u32_add_opAList[] = {
    TV_u32_add_opA_0,
    TV_u32_add_opA_1,
    TV_u32_add_opA_2,
};
const uint32_t* TV_u32_add_opBList[] = {
    TV_u32_add_opB_0,
    TV_u32_add_opB_1,
    TV_u32_add_opB_2,
};
const uint32_t TV_u32_add_carryList[] = {
    TV_u32_add_carry_0,
    TV_u32_add_carry_1,
    TV_u32_add_carry_2,
};

/****************************************************************************************************/
const uint32_t TV_u32_sub_ref_0[] = {
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
};
const uint32_t TV_u32_sub_opA_0[] = {
    0x00000001ul, 0x00000000ul, 0x00000000ul, 0x00000000ul,
};
const uint32_t TV_u32_sub_opB_0[] = {
    0x00000000ul, 0x00000000ul, 0x00000000ul, 0x00000000ul,
};
const uint32_t TV_u32_sub_carry_0 = 0x00000000;

const uint32_t TV_u32_sub_ref_1[] = {
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
};
const uint32_t TV_u32_sub_opA_1[] = {
    0x00000001ul, 0x00000000ul, 0x00000000ul, 0x00000000ul,
};
const uint32_t TV_u32_sub_opB_1[] = {
    0x00000000ul, 0x00000000ul, 0x00000000ul, 0x00000000ul,
};
const uint32_t TV_u32_sub_carry_1 = 0x00000001;

#define TV_U32_SUB_NUM  2u
const size_t TV_u32_sub_lenList[] = {
    sizeof(TV_u32_sub_ref_0),
    sizeof(TV_u32_sub_ref_1),
};
const uint32_t* TV_u32_sub_refList[] = {
    TV_u32_sub_ref_0,
    TV_u32_sub_ref_1,
};
const uint32_t* TV_u32_sub_opAList[] = {
    TV_u32_sub_opA_0,
    TV_u32_sub_opA_1,
};
const uint32_t* TV_u32_sub_opBList[] = {
    TV_u32_sub_opB_0,
    TV_u32_sub_opB_1,
};
const uint32_t TV_u32_sub_carryList[] = {
    TV_u32_sub_carry_0,
    TV_u32_sub_carry_1,
};

#endif  /* VECTOR_H */
