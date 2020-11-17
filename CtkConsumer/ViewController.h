//
//  ViewController.h
//  CtkConsumer
//
//  Created on 10/16/20.
//

#import <UIKit/UIKit.h>
#include <vector>

@interface ViewController : UIViewController
{
@private
    std::vector<SecIdentityRef> identitiesSign, identitiesEnc;
    std::vector<SecCertificateRef> certsSign, certsEnc;
}
- (IBAction)onCollectIds:(id)sender;
- (IBAction)onSign:(id)sender;
- (IBAction)onDecrypt:(id)sender;
@end

