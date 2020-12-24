
#define 	BLUEDOT_TYPE_IP		1
#define		BLUEDOT_TYPE_HASH	2

#define		BLUEDOT_ALERT_ALERT	1
#define		BLUEDOT_ALERT_REPORT	2

typedef struct _Bluedot_IP_Queue _Bluedot_IP_Queue;
struct _Bluedot_IP_Queue
{
    unsigned char ip[MAX_IP_BIT_SIZE];
};

/* IP address to NOT lookup */

typedef struct _Bluedot_Skip _Bluedot_Skip;
struct _Bluedot_Skip
{

    struct
    {
        unsigned char ipbits[MAX_IP_BIT_SIZE];
        unsigned char maskbits[MAX_IP_BIT_SIZE];
    } range;

};


void Bluedot_Init( void );
bool Bluedot( uint32_t rule_position, uint8_t s_position, char *json );

