#include "libopaque.h"
#include <stdio.h>
#include <opaque.h>

int create_cfg(const int skU, const int pkU, const int pkS, const int idU, const int idS, Opaque_PkgConfig *cfg) {
   if(skU!=0 && skU!=1) return 1;
   if(pkU!=0 && pkU!=1 && pkU!=2) return 1;
   if(pkS!=0 && pkS!=1 && pkS!=2) return 1;
   if(idU!=0 && idU!=1 && idU!=2) return 1;
   if(idS!=0 && idS!=1 && idS!=2) return 1;
   cfg->skU = skU;
   cfg->pkU = pkU;
   cfg->pkS = pkS;
   cfg->idU = idU;
   cfg->idS = idS;
   return 0;
}
